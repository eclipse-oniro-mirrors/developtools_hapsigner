/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "perm_sign_test.h"
#include "params_run_tool.h"
#include "local_sign_provider.h"
#include "remote_sign_provider.h"
#include "sign_hap.h"
#include "sign_provider.h"
#include "sign_tool_service_impl.h"
#include "verify_hap.h"
#include "hap_utils.h"
#include "hap_signer_block_utils.h"
#include "byte_buffer.h"
#include "pkcs7_context.h"
#include "signature_algorithm_helper.h"
#include "signature_info.h"
#include "string_utils.h"
#include "cJSON.h"
#include <unistd.h>
#include <openssl/sha.h>
#undef SHA256_DIGEST_LENGTH
static constexpr int SHA256_DIGEST_LENGTH = 32;

namespace OHOS {
namespace SignatureTools {

static constexpr int PERMISSION_SIGN_BLOCK_MIN_SIZE = 12;
static constexpr int TEST_ALGORITHM_SHA256_WITH_ECDSA = 0x10101;
static constexpr int TEST_ALGORITHM_SHA384_WITH_ECDSA = 0x10201;
static constexpr int PERMISSION_SIGN_BLOCK_ID_OFFSET = 0;
static constexpr int PERMISSION_SIGN_BLOCK_SIZE_OFFSET = 4;
static constexpr int PERMISSION_SIGN_RESERVED_OFFSET = 8;
static constexpr int PERMISSION_SIGN_MAGIC_OFFSET = 12;
static constexpr int PERMISSION_SIGN_SIGN_ALG_ID_OFFSET = 20;
static constexpr int PERMISSION_SIGN_DIGEST_LEN_OFFSET = 24;
static constexpr int PERMISSION_SIGN_DIGEST_COUNT_OFFSET = 28;
static constexpr int PERMISSION_SIGN_DIGEST_DATA_OFFSET = 30;
static constexpr int PERMISSION_SIGN_HEADER_SIZE = 12;
static constexpr int PERMISSION_SIGN_FIXED_HEADER_SIZE = 12 + 8 + 4 + 4 + 2;
static constexpr int PERMISSION_SIGN_SIG_LEN_SIZE = 4;

void PermSignTest::SetUpTestCase(void)
{
    sync();
}

void PermSignTest::TearDownTestCase(void)
{
}

static bool ComputeDigestForTest(const std::string& content, std::vector<int8_t>& digest)
{
    if (content.empty()) {
        return false;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(content.c_str()), content.size(), hash);

    digest.resize(SHA256_DIGEST_LENGTH);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        digest[i] = static_cast<int8_t>(hash[i]);
    }
    return true;
}

static ByteBuffer CreateMockPermSignBlock(int32_t signAlgId, int16_t digestCount, const std::string& signature)
{
    ByteBuffer permSignBlock;
    const std::vector<int8_t>& magic = HapUtils::GetPermissionSignMagic();
    
    int32_t digestLen = digestCount * (4 + HapUtils::PERMISSION_SIGN_DIGEST_SIZE);
    int32_t sigLen = signature.size();
    int32_t totalSize = PERMISSION_SIGN_FIXED_HEADER_SIZE + digestLen + 4 + sigLen;
    
    permSignBlock.SetCapacity(totalSize + PERMISSION_SIGN_HEADER_SIZE);
    permSignBlock.SetPosition(0);
    
    permSignBlock.PutInt32(PERMISSION_SIGN_BLOCK_ID_OFFSET, HapUtils::PERMISSION_SIGN_BLOCK_ID);
    permSignBlock.PutInt32(PERMISSION_SIGN_BLOCK_SIZE_OFFSET, totalSize);
    permSignBlock.PutInt32(PERMISSION_SIGN_RESERVED_OFFSET, 0);
    
    permSignBlock.PutData(PERMISSION_SIGN_MAGIC_OFFSET, magic.data(), magic.size());
    permSignBlock.PutInt32(PERMISSION_SIGN_SIGN_ALG_ID_OFFSET, signAlgId);
    permSignBlock.PutInt32(PERMISSION_SIGN_DIGEST_LEN_OFFSET, digestLen);
    permSignBlock.PutInt16(PERMISSION_SIGN_DIGEST_COUNT_OFFSET, digestCount);
    
    int curOffset = PERMISSION_SIGN_DIGEST_DATA_OFFSET;
    std::vector<int8_t> mockDigest(HapUtils::PERMISSION_SIGN_DIGEST_SIZE, 0x01);
    for (int i = 0; i < digestCount; i++) {
        permSignBlock.PutInt32(curOffset, HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION);
        curOffset += HapUtils::PERMISSION_SIGN_DIGEST_TYPE_SIZE;
        permSignBlock.PutData(curOffset, mockDigest.data(), HapUtils::PERMISSION_SIGN_DIGEST_SIZE);
        curOffset += HapUtils::PERMISSION_SIGN_DIGEST_SIZE;
    }
    
    permSignBlock.PutInt32(curOffset, sigLen);
    curOffset += PERMISSION_SIGN_SIG_LEN_SIZE;
    if (sigLen > 0) {
        permSignBlock.PutData(curOffset, signature.data(), sigLen);
    }
    
    return permSignBlock;
}

HWTEST_F(PermSignTest, perm_sign_test_001, testing::ext::TestSize.Level1)
{
    const std::vector<int8_t>& magic = HapUtils::GetPermissionSignMagic();
    EXPECT_EQ(magic.size(), 8);
    EXPECT_NE(magic.size(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_002, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(HapUtils::PERMISSION_SIGN_DIGEST_SIZE, 32);
    EXPECT_EQ(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION, 0x00000001);
    EXPECT_EQ(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_MODULE_JSON, 0x00000002);
    EXPECT_EQ(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_CODE_SIGN_BLOCK, 0x00000003);
    EXPECT_EQ(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_SHARED_FILE, 0x00000004);
}

HWTEST_F(PermSignTest, perm_sign_test_003, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(HapUtils::PERMISSION_SIGN_BLOCK_ID, 0x30000002);
    EXPECT_EQ(HapUtils::HAP_CODE_SIGN_BLOCK_ID, 0x30000001);
    EXPECT_EQ(HapUtils::HAP_PROPERTY_BLOCK_ID, 0x20000003);
}

HWTEST_F(PermSignTest, perm_sign_test_004, testing::ext::TestSize.Level1)
{
    std::string content = "test content for digest computation";
    std::vector<int8_t> digest;
    bool result = ComputeDigestForTest(content, digest);
    EXPECT_EQ(result, true);
    EXPECT_EQ(digest.size(), SHA256_DIGEST_LENGTH);
}

HWTEST_F(PermSignTest, perm_sign_test_005, testing::ext::TestSize.Level1)
{
    std::string emptyContent = "";
    std::vector<int8_t> digest;
    bool result = ComputeDigestForTest(emptyContent, digest);
    EXPECT_EQ(result, false);
}

HWTEST_F(PermSignTest, perm_sign_test_006, testing::ext::TestSize.Level1)
{
    std::string content1 = "content1";
    std::string content2 = "content2";
    std::vector<int8_t> digest1, digest2;
    
    ComputeDigestForTest(content1, digest1);
    ComputeDigestForTest(content2, digest2);
    
    EXPECT_NE(digest1, digest2);
}

HWTEST_F(PermSignTest, perm_sign_test_007, testing::ext::TestSize.Level1)
{
    std::string content = "same content";
    std::vector<int8_t> digest1, digest2;
    
    ComputeDigestForTest(content, digest1);
    ComputeDigestForTest(content, digest2);
    
    EXPECT_EQ(digest1, digest2);
}

HWTEST_F(PermSignTest, perm_sign_test_008, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 1, "");
    EXPECT_GT(permSignBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_009, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA384_WITH_ECDSA, 2, "test_signature");
    EXPECT_GT(permSignBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_010, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 0, "");
    EXPECT_GT(permSignBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_011, testing::ext::TestSize.Level1)
{
    ByteBuffer emptyBlock;
    emptyBlock.SetCapacity(0);
    EXPECT_EQ(emptyBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_012, testing::ext::TestSize.Level1)
{
    ByteBuffer smallBlock;
    smallBlock.SetCapacity(10);
    EXPECT_EQ(smallBlock.GetCapacity(), 10);
    EXPECT_LT(smallBlock.GetCapacity(), PERMISSION_SIGN_BLOCK_MIN_SIZE);
}

HWTEST_F(PermSignTest, perm_sign_test_013, testing::ext::TestSize.Level1)
{
    ByteBuffer block;
    block.SetCapacity(100);
    block.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
    block.PutInt32(50);
    block.PutInt32(0);
    
    EXPECT_GT(block.GetCapacity(), PERMISSION_SIGN_BLOCK_MIN_SIZE);
}

HWTEST_F(PermSignTest, perm_sign_test_014, testing::ext::TestSize.Level1)
{
    const std::vector<int8_t>& magic = HapUtils::GetPermissionSignMagic();
    ByteBuffer block;
    block.SetCapacity(100);
    block.PutData(reinterpret_cast<const char*>(magic.data()), magic.size());
    
    EXPECT_EQ(block.GetCapacity(), 100);
}

HWTEST_F(PermSignTest, perm_sign_test_015, testing::ext::TestSize.Level1)
{
    std::string moduleJson = "{\"module\": {\"name\": \"test_module\"}}";
    EXPECT_FALSE(moduleJson.empty());
}

HWTEST_F(PermSignTest, perm_sign_test_016, testing::ext::TestSize.Level1)
{
    std::string invalidJson = "invalid json content";
    cJSON* root = cJSON_ParseWithOpts(invalidJson.c_str(), nullptr, 1);
    EXPECT_EQ(root, nullptr);
}

HWTEST_F(PermSignTest, perm_sign_test_017, testing::ext::TestSize.Level1)
{
    std::string validJson = "{\"module\": {\"shareFiles\": \"test_share\"}}";
    cJSON* root = cJSON_ParseWithOpts(validJson.c_str(), nullptr, 1);
    EXPECT_NE(root, nullptr);
    cJSON_Delete(root);
}

HWTEST_F(PermSignTest, perm_sign_test_018, testing::ext::TestSize.Level1)
{
    std::vector<std::pair<int, std::vector<int8_t>>> digestItems;
    std::vector<int8_t> mockDigest(SHA256_DIGEST_LENGTH, 0x01);
    digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION, mockDigest});
    digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_MODULE_JSON, mockDigest});
    
    EXPECT_EQ(digestItems.size(), 2);
}

HWTEST_F(PermSignTest, perm_sign_test_019, testing::ext::TestSize.Level1)
{
    std::string allDigests;
    std::vector<int8_t> mockDigest(SHA256_DIGEST_LENGTH, 0x01);
    allDigests.append(reinterpret_cast<const char*>(mockDigest.data()), mockDigest.size());
    allDigests.append(reinterpret_cast<const char*>(mockDigest.data()), mockDigest.size());
    
    EXPECT_EQ(allDigests.size(), SHA256_DIGEST_LENGTH * 2);
}

HWTEST_F(PermSignTest, perm_sign_test_020, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    ByteBuffer propertyBlockArray;
    propertyBlockArray.SetCapacity(12);
    propertyBlockArray.SetPosition(0);
    propertyBlockArray.PutInt32(0, HapUtils::HAP_CODE_SIGN_BLOCK_ID);
    propertyBlockArray.PutInt32(4, 0);
    propertyBlockArray.PutInt32(8, 0);
    
    bool result = verify.CheckFileNameAndBlockArray("test.hap", propertyBlockArray);
    EXPECT_EQ(result, true);
}

HWTEST_F(PermSignTest, perm_sign_test_021, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    ByteBuffer propertyBlockArray;
    propertyBlockArray.SetCapacity(50);
    propertyBlockArray.PutInt32(HapUtils::HAP_CODE_SIGN_BLOCK_ID);
    propertyBlockArray.PutInt32(10);
    propertyBlockArray.PutInt32(0);
    
    bool result = verify.CheckFileNameAndBlockArray("test.hap", propertyBlockArray);
    EXPECT_EQ(result, true);
}

HWTEST_F(PermSignTest, perm_sign_test_022, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    ByteBuffer propertyBlockArray;
    propertyBlockArray.SetCapacity(50);
    propertyBlockArray.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
    propertyBlockArray.PutInt32(10);
    propertyBlockArray.PutInt32(0);
    
    bool result = verify.CheckFileNameAndBlockArray("test.hap", propertyBlockArray);
    EXPECT_EQ(result, true);
}

HWTEST_F(PermSignTest, perm_sign_test_023, testing::ext::TestSize.Level1)
{
    std::string profileContent = "{\"version\":\"1.0\",\"type\":\"release\"}";
    EXPECT_FALSE(profileContent.empty());
}

HWTEST_F(PermSignTest, perm_sign_test_024, testing::ext::TestSize.Level1)
{
    std::string profileContent = "";
    std::string cleanContent;
    VerifyHap verify;
    int result = verify.GetProfileContent(profileContent, cleanContent);
    EXPECT_NE(result, 0);
}

HWTEST_F(PermSignTest, perm_sign_test_025, testing::ext::TestSize.Level1)
{
    std::string profileContent = "{\"valid\":\"json\"}";
    std::string cleanContent;
    VerifyHap verify;
    int result = verify.GetProfileContent(profileContent, cleanContent);
    EXPECT_EQ(result, 0);
}

HWTEST_F(PermSignTest, perm_sign_test_026, testing::ext::TestSize.Level1)
{
    SignatureInfo hapSignInfo;
    EXPECT_TRUE(hapSignInfo.optionBlocks.empty());
}

HWTEST_F(PermSignTest, perm_sign_test_027, testing::ext::TestSize.Level1)
{
    SignatureInfo hapSignInfo;
    ByteBuffer mockBlock;
    mockBlock.SetCapacity(10);
    OptionalBlock block = {HapUtils::HAP_PROFILE_BLOCK_ID, mockBlock};
    hapSignInfo.optionBlocks.push_back(block);
    
    EXPECT_EQ(hapSignInfo.optionBlocks.size(), 1);
}

HWTEST_F(PermSignTest, perm_sign_test_028, testing::ext::TestSize.Level1)
{
    SignatureInfo hapSignInfo;
    ByteBuffer mockBlock;
    mockBlock.SetCapacity(10);
    OptionalBlock block = {HapUtils::HAP_PROPERTY_BLOCK_ID, mockBlock};
    hapSignInfo.optionBlocks.push_back(block);
    
    VerifyHap verify;
    bool result = verify.IsVerifyResign(hapSignInfo);
    EXPECT_EQ(result, false);
}

HWTEST_F(PermSignTest, perm_sign_test_029, testing::ext::TestSize.Level1)
{
    SignatureInfo hapSignInfo;
    ByteBuffer mockBlock;
    mockBlock.SetCapacity(10);
    OptionalBlock block = {HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID, mockBlock};
    hapSignInfo.optionBlocks.push_back(block);
    
    VerifyHap verify;
    bool result = verify.IsVerifyResign(hapSignInfo);
    EXPECT_EQ(result, true);
}

HWTEST_F(PermSignTest, perm_sign_test_030, testing::ext::TestSize.Level1)
{
    std::string shareFilePath = "$profile:test_share";
    std::string actualFilePath = shareFilePath;
    if (shareFilePath.find("$profile:") == 0) {
        actualFilePath = "resources/base/profile/" + shareFilePath.substr(9) + ".json";
    }
    EXPECT_EQ(actualFilePath, "resources/base/profile/test_share.json");
}

HWTEST_F(PermSignTest, perm_sign_test_031, testing::ext::TestSize.Level1)
{
    std::string shareFilePath = "direct_path.json";
    std::string actualFilePath = shareFilePath;
    if (shareFilePath.find("$profile:") == 0) {
        actualFilePath = "resources/base/profile/" + shareFilePath.substr(9) + ".json";
    }
    EXPECT_EQ(actualFilePath, "direct_path.json");
}

HWTEST_F(PermSignTest, perm_sign_test_032, testing::ext::TestSize.Level1)
{
    std::vector<int32_t> digestTypes;
    digestTypes.push_back(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION);
    digestTypes.push_back(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_MODULE_JSON);
    digestTypes.push_back(HapUtils::PERMISSION_SIGN_DIGEST_TYPE_CODE_SIGN_BLOCK);
    
    EXPECT_EQ(digestTypes.size(), 3);
}

HWTEST_F(PermSignTest, perm_sign_test_033, testing::ext::TestSize.Level1)
{
    int32_t signAlgId = TEST_ALGORITHM_SHA256_WITH_ECDSA;
    const EVP_MD* hash = nullptr;
    
    if (signAlgId == TEST_ALGORITHM_SHA256_WITH_ECDSA) {
        hash = EVP_sha256();
    } else if (signAlgId == TEST_ALGORITHM_SHA384_WITH_ECDSA) {
        hash = EVP_sha384();
    }
    
    EXPECT_NE(hash, nullptr);
}

HWTEST_F(PermSignTest, perm_sign_test_034, testing::ext::TestSize.Level1)
{
    int32_t signAlgId = TEST_ALGORITHM_SHA384_WITH_ECDSA;
    const EVP_MD* hash = nullptr;
    
    if (signAlgId == TEST_ALGORITHM_SHA256_WITH_ECDSA) {
        hash = EVP_sha256();
    } else if (signAlgId == TEST_ALGORITHM_SHA384_WITH_ECDSA) {
        hash = EVP_sha384();
    }
    
    EXPECT_NE(hash, nullptr);
}

HWTEST_F(PermSignTest, perm_sign_test_035, testing::ext::TestSize.Level1)
{
    int32_t unsupportedAlgId = 0x99999999;
    const EVP_MD* hash = nullptr;
    bool supported = false;
    
    if (unsupportedAlgId == TEST_ALGORITHM_SHA256_WITH_ECDSA) {
        hash = EVP_sha256();
        supported = true;
    } else if (unsupportedAlgId == TEST_ALGORITHM_SHA384_WITH_ECDSA) {
        hash = EVP_sha384();
        supported = true;
    }
    
    EXPECT_EQ(supported, false);
}

HWTEST_F(PermSignTest, perm_sign_test_036, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 3, "signature_data");
    permSignBlock.SetPosition(0);
    
    uint32_t blockType;
    permSignBlock.GetUInt32(0, blockType);
    EXPECT_EQ(blockType, HapUtils::PERMISSION_SIGN_BLOCK_ID);
}

HWTEST_F(PermSignTest, perm_sign_test_037, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 1, "");
    
    const std::vector<int8_t>& magic = HapUtils::GetPermissionSignMagic();
    for (int i = 0; i < 8; i++) {
        int8_t val;
        permSignBlock.GetInt8(12 + i, val);
        EXPECT_EQ(val, magic[i]);
    }
}

HWTEST_F(PermSignTest, perm_sign_test_038, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 2, "test");
    
    int32_t signAlgId;
    permSignBlock.GetInt32(20, signAlgId);
    EXPECT_EQ(signAlgId, TEST_ALGORITHM_SHA256_WITH_ECDSA);
}

HWTEST_F(PermSignTest, perm_sign_test_039, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA384_WITH_ECDSA, 1, "");
    
    int32_t signAlgId;
    permSignBlock.GetInt32(20, signAlgId);
    EXPECT_EQ(signAlgId, TEST_ALGORITHM_SHA384_WITH_ECDSA);
}

HWTEST_F(PermSignTest, perm_sign_test_040, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 5, "");
    
    int16_t num;
    permSignBlock.GetInt16(28, num);
    EXPECT_EQ(num, 5);
}

HWTEST_F(PermSignTest, perm_sign_test_041, testing::ext::TestSize.Level1)
{
    std::string emptySignature = "";
    EXPECT_TRUE(emptySignature.empty());
}

HWTEST_F(PermSignTest, perm_sign_test_042, testing::ext::TestSize.Level1)
{
    std::string signature = "valid_signature_data";
    EXPECT_FALSE(signature.empty());
    EXPECT_GT(signature.size(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_043, testing::ext::TestSize.Level1)
{
    ByteBuffer codeSignBlock;
    codeSignBlock.SetCapacity(100);
    EXPECT_GT(codeSignBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_044, testing::ext::TestSize.Level1)
{
    ByteBuffer codeSignBlock;
    codeSignBlock.SetCapacity(0);
    EXPECT_EQ(codeSignBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_045, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    EXPECT_TRUE(pkcs7Context.certChain.empty());
}

HWTEST_F(PermSignTest, perm_sign_test_046, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> data;
    data.push_back(0x01);
    data.push_back(0x02);
    data.push_back(0x03);
    
    std::vector<int8_t> digest;
    bool result = ComputeDigestForTest(std::string(data.data(), data.data() + data.size()), digest);
    EXPECT_EQ(result, true);
    EXPECT_EQ(digest.size(), SHA256_DIGEST_LENGTH);
}

HWTEST_F(PermSignTest, perm_sign_test_047, testing::ext::TestSize.Level1)
{
    ByteBuffer propertyBlock;
    propertyBlock.SetCapacity(200);
    propertyBlock.SetPosition(0);
    propertyBlock.PutInt32(0, HapUtils::HAP_CODE_SIGN_BLOCK_ID);
    propertyBlock.PutInt32(4, 100);
    propertyBlock.PutInt32(8, 0);
    
    uint32_t blockType;
    propertyBlock.GetUInt32(0, blockType);
    EXPECT_EQ(blockType, HapUtils::HAP_CODE_SIGN_BLOCK_ID);
}

HWTEST_F(PermSignTest, perm_sign_test_048, testing::ext::TestSize.Level1)
{
    ByteBuffer permSignSubBlock = CreateMockPermSignBlock(TEST_ALGORITHM_SHA256_WITH_ECDSA, 2, "sig");
    
    ByteBuffer propertyBlock;
    propertyBlock.SetCapacity(permSignSubBlock.GetCapacity() + 12);
    propertyBlock.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
    propertyBlock.PutInt32(permSignSubBlock.GetCapacity() - 12);
    propertyBlock.PutInt32(0);
    
    EXPECT_GT(propertyBlock.GetCapacity(), 0);
}

HWTEST_F(PermSignTest, perm_sign_test_049, testing::ext::TestSize.Level1)
{
    std::string allDigests;
    for (int i = 0; i < 3; i++) {
        std::vector<int8_t> mockDigest(SHA256_DIGEST_LENGTH, (int8_t)(i + 1));
        allDigests.append(reinterpret_cast<const char*>(mockDigest.data()), mockDigest.size());
    }
    EXPECT_EQ(allDigests.size(), SHA256_DIGEST_LENGTH * 3);
}

} // namespace SignatureTools
} // namespace OHOS