/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <openssl/sha.h>

#include "sign_provider.h"
#include "verify_hap.h"
#include "hap_utils.h"
#include "byte_buffer.h"
#include "local_sign_provider.h"
#include "options.h"
#include "signature_info.h"
#include "pkcs7_context.h"
#include "cJSON.h"

namespace OHOS {
namespace SignatureTools {

static constexpr int ALGORITHM_SHA256_WITH_ECDSA = 0x10101;
static constexpr int ALGORITHM_SHA384_WITH_ECDSA = 0x10201;
static constexpr int PERMISSION_SIGN_BLOCK_MIN_SIZE = 12;
static constexpr int PERMISSION_SIGN_MAGIC_OFFSET = 12;
static constexpr int PERMISSION_SIGN_SIGN_ALG_ID_OFFSET = 20;
static constexpr int PERMISSION_SIGN_DIGEST_COUNT_OFFSET = 28;
static constexpr int PERMISSION_SIGN_MAGIC_LENGTH = 8;
static constexpr int PERMISSION_SIGN_DIGEST_TYPE_OFFSET = 30;
static constexpr int PERMISSION_SIGN_BLOCK_TYPE_OFFSET = 0;
static constexpr int PERMISSION_SIGN_BLOCK_LENGTH_OFFSET = 4;
static constexpr int PERMISSION_SIGN_BLOCK_OFFSET_OFFSET = 8;
static constexpr int SHA256_DIGEST_SIZE = 32;
static constexpr int SHA384_DIGEST_SIZE = 48;
static constexpr int MAX_DIGEST_ITEMS_LOOP = 4;
static constexpr int PERMISSION_SIGN_BLOCK_MIN_CAPACITY = 24;
static constexpr int PERMISSION_SIGN_MIN_CAPACITY = 30;
static constexpr int PERMISSION_SIGN_MIN_CAPACITY_FOR_DIGEST = 34;
static constexpr int PERMISSION_SIGN_SIG_CHECK_CAPACITY = 100;
static constexpr int PERMISSION_SIGN_SIG_LEN_SIZE = 4;
static constexpr int PERMISSION_SIGN_DIGEST_DATA_OFFSET = 30;
static constexpr int PERMISSION_SIGN_PROFILE_PREFIX_LEN = 9;

static bool ComputeDigestForFuzz(const std::vector<uint8_t>& content, std::vector<int8_t>& digest)
{
    if (content.empty()) {
        return false;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(content.data(), content.size(), hash);

    digest.resize(SHA256_DIGEST_LENGTH);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        digest[i] = static_cast<int8_t>(hash[i]);
    }
    return true;
}

static ByteBuffer CreatePermSignBlockFromFuzzData(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock;
    if (size < PERMISSION_SIGN_BLOCK_MIN_SIZE) {
        permSignBlock.SetCapacity(PERMISSION_SIGN_BLOCK_MIN_SIZE);
        permSignBlock.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
        permSignBlock.PutInt32(0);
        permSignBlock.PutInt32(0);
        return permSignBlock;
    }
    permSignBlock.SetCapacity(size + PERMISSION_SIGN_BLOCK_MIN_SIZE);
    permSignBlock.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
    permSignBlock.PutInt32(static_cast<int32_t>(size));
    permSignBlock.PutInt32(0);
    permSignBlock.PutData(reinterpret_cast<const char*>(data), size);
    return permSignBlock;
}

void PermSignBlockMagicCheck(const uint8_t* data, size_t size)
{
    const std::vector<int8_t>& magic = HapUtils::GetPermissionSignMagic();
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    if (permSignBlock.GetCapacity() < PERMISSION_SIGN_BLOCK_MIN_SIZE + PERMISSION_SIGN_MAGIC_LENGTH) {
        return;
    }
    
    permSignBlock.SetPosition(PERMISSION_SIGN_MAGIC_OFFSET);
    for (int i = 0; i < PERMISSION_SIGN_MAGIC_LENGTH && i < static_cast<int>(size); i++) {
        int8_t val;
        permSignBlock.GetInt8(PERMISSION_SIGN_MAGIC_OFFSET + i, val);
        if (val != magic[i]) {
            return;
        }
    }
}

void PermSignDigestComputation(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> content(data, data + size);
    std::vector<int8_t> digest;
    ComputeDigestForFuzz(content, digest);
}

void PermSignBlockTypeCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    
    uint32_t blockType;
    if (permSignBlock.GetCapacity() >= PERMISSION_SIGN_BLOCK_MIN_SIZE) {
        permSignBlock.GetUInt32(PERMISSION_SIGN_BLOCK_TYPE_OFFSET, blockType);
    }
}

void PermSignBlockLengthCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    uint32_t blockLength;
    if (permSignBlock.GetCapacity() >= PERMISSION_SIGN_BLOCK_MIN_SIZE) {
        permSignBlock.GetUInt32(PERMISSION_SIGN_BLOCK_LENGTH_OFFSET, blockLength);
    }
}

void PermSignBlockOffsetCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    uint32_t blockOffset;
    if (permSignBlock.GetCapacity() >= PERMISSION_SIGN_BLOCK_MIN_SIZE) {
        permSignBlock.GetUInt32(PERMISSION_SIGN_BLOCK_OFFSET_OFFSET, blockOffset);
    }
}

void PermSignAlgorithmIdCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    if (permSignBlock.GetCapacity() < PERMISSION_SIGN_BLOCK_MIN_CAPACITY) {
        return;
    }
    
    int32_t signAlgId;
    permSignBlock.GetInt32(PERMISSION_SIGN_SIGN_ALG_ID_OFFSET, signAlgId);
    const EVP_MD* hash = nullptr;
    if (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) {
        hash = EVP_sha256();
    } else if (signAlgId == ALGORITHM_SHA384_WITH_ECDSA) {
        hash = EVP_sha384();
    }
}

void PermSignDigestCountCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    if (permSignBlock.GetCapacity() < PERMISSION_SIGN_MIN_CAPACITY) {
        return;
    }
    
    int16_t num;
    permSignBlock.GetInt16(PERMISSION_SIGN_DIGEST_COUNT_OFFSET, num);
}

void PermSignDigestTypeCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    if (permSignBlock.GetCapacity() < PERMISSION_SIGN_MIN_CAPACITY_FOR_DIGEST) {
        return;
    }
    int32_t digestType;
    permSignBlock.GetInt32(PERMISSION_SIGN_DIGEST_TYPE_OFFSET, digestType);
}

void PermSignSignatureLengthCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock = CreatePermSignBlockFromFuzzData(data, size);
    if (permSignBlock.GetCapacity() < PERMISSION_SIGN_SIG_CHECK_CAPACITY) {
        return;
    }
    int16_t num = 1;
    int32_t sigPos = PERMISSION_SIGN_DIGEST_DATA_OFFSET + num * 36;
    int32_t sigLen;
    if (sigPos + PERMISSION_SIGN_SIG_LEN_SIZE <= permSignBlock.GetCapacity()) {
        permSignBlock.GetInt32(sigPos, sigLen);
    }
}

void PermSignAllDigestsComputation(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> profileContent(data, data + size);
    std::string hapFilePath = "./permSign/test.hap";
    ByteBuffer codeSignBlock;
    
    std::vector<int32_t> digestTypes;
    digestTypes.push_back(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION);
    
    std::string allDigests;
    std::vector<int8_t> digest;
    if (ComputeDigestForFuzz(profileContent, digest)) {
        allDigests.append(reinterpret_cast<const char*>(digest.data()), digest.size());
    }
}

void PermSignProfileContentCheck(const uint8_t* data, size_t size)
{
    std::string profile(reinterpret_cast<const char*>(data), size);
    std::string cleanContent;

    std::string parseBuffer = profile;
    cJSON* obj = cJSON_ParseWithOpts(parseBuffer.data(), nullptr, 1);
    if (obj != nullptr && (cJSON_IsObject(obj) || cJSON_IsArray(obj))) {
        cleanContent = profile;
        cJSON_Delete(obj);
    } else {
        if (obj != nullptr) {
            cJSON_Delete(obj);
        }
    }
}

void PermSignModuleJsonParse(const uint8_t* data, size_t size)
{
    std::string moduleJsonContent(reinterpret_cast<const char*>(data), size);

    std::string parseBuffer = moduleJsonContent;
    cJSON* root = cJSON_ParseWithOpts(parseBuffer.data(), nullptr, 1);
    if (root == nullptr) {
        return;
    }
    
    cJSON* moduleObj = cJSON_GetObjectItem(root, "module");
    if (moduleObj == nullptr) {
        cJSON_Delete(root);
        return;
    }
    
    cJSON* shareFilesObj = cJSON_GetObjectItem(moduleObj, "shareFiles");
    if (shareFilesObj != nullptr && cJSON_IsString(shareFilesObj)) {
        std::string shareFile = shareFilesObj->valuestring;
    }
    
    cJSON_Delete(root);
}

void PermSignSharedFilePathProcess(const uint8_t* data, size_t size)
{
    std::string shareFilePath(reinterpret_cast<const char*>(data), size);
    std::string actualFilePath = shareFilePath;
    
    if (shareFilePath.find("$profile:") == 0 && shareFilePath.size() > PERMISSION_SIGN_PROFILE_PREFIX_LEN) {
        actualFilePath = "resources/base/profile/" + shareFilePath.substr(PERMISSION_SIGN_PROFILE_PREFIX_LEN) + ".json";
    }
}

void PermSignBlockCapacityCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock;
    permSignBlock.SetCapacity(size);
    
    if (permSignBlock.GetCapacity() < PERMISSION_SIGN_BLOCK_MIN_SIZE) {
        return;
    }
}

void PermSignVerifyBlockCheck(const uint8_t* data, size_t size)
{
    VerifyHap verify;
    ByteBuffer propertyBlockArray;
    
    propertyBlockArray.SetCapacity(size + PERMISSION_SIGN_BLOCK_MIN_SIZE);
    if (size > 0) {
        propertyBlockArray.PutData(reinterpret_cast<const char*>(data), size);
    }
    
    if (propertyBlockArray.GetCapacity() < PERMISSION_SIGN_BLOCK_MIN_SIZE) {
        return;
    }
    
    verify.CheckFileNameAndBlockArray("test.hap", propertyBlockArray);
}

void PermSignSignatureBufferCheck(const uint8_t* data, size_t size)
{
    ByteBuffer permSignBlock;
    permSignBlock.SetCapacity(size + PERMISSION_SIGN_BLOCK_MIN_SIZE);
    permSignBlock.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
    permSignBlock.PutInt32(static_cast<int32_t>(size));
    permSignBlock.PutInt32(0);
    
    if (size > 0) {
        permSignBlock.PutData(reinterpret_cast<const char*>(data), size);
    }
    
    std::string signature(reinterpret_cast<const char*>(data),
        std::min(size, static_cast<size_t>(PERMISSION_SIGN_SIG_CHECK_CAPACITY)));
}

void PermSignDigestItemsBuild(const uint8_t* data, size_t size)
{
    std::vector<std::pair<int, std::vector<int8_t>>> digestItems;
    
    std::vector<int8_t> mockDigest(SHA256_DIGEST_LENGTH, 0x01);
    if (size > 0) {
        for (size_t i = 0; i < std::min(size, static_cast<size_t>(MAX_DIGEST_ITEMS_LOOP)); i++) {
            mockDigest[i % SHA256_DIGEST_LENGTH] = static_cast<int8_t>(data[i]);
        }
    }
    
    digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION, mockDigest});
    digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_MODULE_JSON, mockDigest});
}

void PermSignOptionsCheck(const uint8_t* data, size_t size)
{
    Options options;
    
    std::string permMode(reinterpret_cast<const char*>(data), std::min(size, static_cast<size_t>(10)));
    options["permSign"] = permMode;
    
    std::string signCode(reinterpret_cast<const char*>(data), std::min(size, static_cast<size_t>(10)));
    options["signCode"] = signCode;
}

void PermSignProviderParamsCheck(const uint8_t* data, size_t size)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    
    std::string mode = "localSign";
    std::string keyAlias(reinterpret_cast<const char*>(data), std::min(size, static_cast<size_t>(20)));
    std::string signAlg = "SHA256withECDSA";
    std::string permMode(reinterpret_cast<const char*>(data), std::min(size, static_cast<size_t>(1)));
    
    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["permSign"] = permMode;
}

void PermSignSignatureInfoBuild(const uint8_t* data, size_t size)
{
    SignatureInfo hapSignInfo;
    
    ByteBuffer mockBlock;
    mockBlock.SetCapacity(size);
    if (size > 0) {
        mockBlock.PutData(reinterpret_cast<const char*>(data), size);
    }
    
    OptionalBlock profileBlock = {HapUtils::HAP_PROFILE_BLOCK_ID, mockBlock};
    OptionalBlock propertyBlock = {HapUtils::HAP_PROPERTY_BLOCK_ID, mockBlock};
    
    hapSignInfo.optionBlocks.push_back(profileBlock);
    hapSignInfo.optionBlocks.push_back(propertyBlock);
    
    VerifyHap verify;
    verify.IsVerifyResign(hapSignInfo);
}

void PermSignHashAlgorithmCheck(const uint8_t* data, size_t size)
{
    int32_t signAlgId = static_cast<int32_t>(size % 2 == 0 ? ALGORITHM_SHA256_WITH_ECDSA : ALGORITHM_SHA384_WITH_ECDSA);
    
    const EVP_MD* hash = nullptr;
    int32_t digestSize = 0;
    
    if (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) {
        hash = EVP_sha256();
        digestSize = SHA256_DIGEST_SIZE;
    } else if (signAlgId == ALGORITHM_SHA384_WITH_ECDSA) {
        hash = EVP_sha384();
        digestSize = SHA384_DIGEST_SIZE;
    }
}

void PermSignByteBufferPutData(const uint8_t* data, size_t size)
{
    ByteBuffer buffer;
    buffer.SetCapacity(size + PERMISSION_SIGN_SIG_CHECK_CAPACITY);
    
    if (size > 0) {
        buffer.PutData(reinterpret_cast<const char*>(data), size);
    }
    
    buffer.PutInt32(static_cast<int32_t>(size));
    buffer.PutInt16(static_cast<int16_t>(size % PERMISSION_SIGN_SIG_CHECK_CAPACITY));
}

void PermSignPkcs7ContextCheck(const uint8_t* data, size_t size)
{
    Pkcs7Context pkcs7Context;
    ByteBuffer content;
    
    content.SetCapacity(size);
    if (size > 0) {
        content.PutData(reinterpret_cast<const char*>(data), size);
    }
    
    pkcs7Context.content = content;
}

void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    PermSignBlockMagicCheck(data, size);
    PermSignDigestComputation(data, size);
    PermSignBlockTypeCheck(data, size);
    PermSignBlockLengthCheck(data, size);
    PermSignBlockOffsetCheck(data, size);
    PermSignAlgorithmIdCheck(data, size);
    PermSignDigestCountCheck(data, size);
    PermSignDigestTypeCheck(data, size);
    PermSignSignatureLengthCheck(data, size);
    PermSignAllDigestsComputation(data, size);
    PermSignProfileContentCheck(data, size);
    PermSignModuleJsonParse(data, size);
    PermSignSharedFilePathProcess(data, size);
    PermSignBlockCapacityCheck(data, size);
    PermSignVerifyBlockCheck(data, size);
    PermSignSignatureBufferCheck(data, size);
    PermSignDigestItemsBuild(data, size);
    PermSignOptionsCheck(data, size);
    PermSignProviderParamsCheck(data, size);
    PermSignSignatureInfoBuild(data, size);
    PermSignHashAlgorithmCheck(data, size);
    PermSignByteBufferPutData(data, size);
    PermSignPkcs7ContextCheck(data, size);
}
} // namespace SignatureTools
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SignatureTools::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}