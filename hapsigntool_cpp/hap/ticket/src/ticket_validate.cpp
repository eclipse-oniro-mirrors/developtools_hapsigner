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
#include "ticket_validate.h"

#include "securec.h"
#include "signature_tools_errno.h"
#include "signature_tools_log.h"
#include "constant.h"
#include "hap_signer_block_utils.h"
#include "hap_utils.h"
#include "pkcs7_data.h"
#include "profile_verify.h"
#include "verify_hap.h"

namespace OHOS {
namespace SignatureTools {

static constexpr int HEX_CHARS_PER_BYTE = 2;
static constexpr int HEX_BYTE_STR_SIZE = HEX_CHARS_PER_BYTE + 1;

static std::string HashToHex(const unsigned char* hash, unsigned int hashLen)
{
    std::string hashHex;
    hashHex.reserve(hashLen * HEX_CHARS_PER_BYTE);
    char hexByte[HEX_BYTE_STR_SIZE] = {0};
    for (unsigned int i = 0; i < hashLen; i++) {
        if (snprintf_s(hexByte, sizeof(hexByte), HEX_CHARS_PER_BYTE, "%02x", hash[i]) < 0) {
            return "";
        }
        hashHex += hexByte;
    }
    return hashHex;
}

const EVP_MD* TicketValidate::GetHashMd(TicketHashType hashType)
{
    switch (hashType) {
        case TICKET_HASH_SHA256:
            return EVP_sha256();
        case TICKET_HASH_SHA384:
            return EVP_sha384();
        case TICKET_HASH_SHA512:
            return EVP_sha512();
        default:
            return EVP_sha256();
    }
}

std::string TicketValidate::ComputeHashHex(const char* data, int len, TicketHashType hashType)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    EVP_Digest(data, static_cast<size_t>(len), hash, &hashLen, GetHashMd(hashType), nullptr);
    return HashToHex(hash, hashLen);
}

std::string TicketValidate::ComputeHashHexStream(unzFile zFile, TicketHashType hashType)
{
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (mdCtx == nullptr) {
        return "";
    }
    EVP_DigestInit(mdCtx, GetHashMd(hashType));
    char buf[4096];
    int readSize = 0;
    while ((readSize = unzReadCurrentFile(zFile, buf, sizeof(buf))) > 0) {
        EVP_DigestUpdate(mdCtx, buf, static_cast<size_t>(readSize));
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    EVP_DigestFinal(mdCtx, hash, &hashLen);
    EVP_MD_CTX_free(mdCtx);
    if (readSize < 0) {
        return "";
    }
    return HashToHex(hash, hashLen);
}

TicketValidate::TicketHashType TicketValidate::ParseHashTypeFromField(const std::string& fieldName)
{
    if (fieldName.find("SHA-256") != std::string::npos) {
        return TICKET_HASH_SHA256;
    }
    if (fieldName.find("SHA-384") != std::string::npos) {
        return TICKET_HASH_SHA384;
    }
    if (fieldName.find("SHA-512") != std::string::npos) {
        return TICKET_HASH_SHA512;
    }
    return TICKET_HASH_SHA256;
}

std::string TicketValidate::FindHashField(void* obj, TicketHashType& outType)
{
    static const std::vector<std::string> hashFields = {
        "SHA-256-Digest", "SHA-384-Digest", "SHA-512-Digest"
    };
    cJSON* cobj = static_cast<cJSON*>(obj);
    for (const auto& field : hashFields) {
        cJSON* val = cJSON_GetObjectItem(cobj, field.c_str());
        if (cJSON_IsString(val)) {
            outType = ParseHashTypeFromField(field);
            return cJSON_GetStringValue(val);
        }
    }
    outType = TICKET_HASH_SHA256;
    return "";
}

bool TicketValidate::ExtractTicketP7b(const SignatureInfo& signInfo, std::string& ticketP7b)
{
    std::string hapSigDer(signInfo.hapSignatureBlock.GetBufferPtr(),
        signInfo.hapSignatureBlock.GetCapacity());
    PKCS7Data p7Data;
    if (p7Data.Parse(hapSigDer) < 0) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse hap signature pkcs7 failed");
        return false;
    }
    if (p7Data.GetUnauthenticatedAttribute(NOTARIZATION_TICKET_OID, ticketP7b) < 0) {
        PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR,
            "notarization ticket not found in unauth_attr");
        return false;
    }
    return true;
}

void TicketValidate::ParseFileHashes(cJSON* root, std::vector<FileHashEntry>& fileHashes)
{
    cJSON* files = cJSON_GetObjectItem(root, "files");
    if (files == nullptr || !cJSON_IsArray(files)) {
        return;
    }
    int arrSize = cJSON_GetArraySize(files);
    for (int i = 0; i < arrSize; i++) {
        cJSON* item = cJSON_GetArrayItem(files, i);
        cJSON* path = cJSON_GetObjectItem(item, "path");
        TicketHashType type = TICKET_HASH_SHA256;
        std::string hashVal = FindHashField(item, type);
        if (cJSON_IsString(path) && !hashVal.empty()) {
            fileHashes.push_back({cJSON_GetStringValue(path), hashVal, type});
        }
    }
}

bool TicketValidate::ParseTicketJson(const std::string& ticketJson, ValidateContext& ctx)
{
    cJSON* root = cJSON_ParseWithOpts(ticketJson.c_str(), nullptr, 1);
    if (root == nullptr) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse notarization ticket JSON failed");
        return false;
    }
    cJSON* version = cJSON_GetObjectItem(root, "version");
    if (!cJSON_IsNumber(version) || version->valueint != 1) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR,
            "unsupported notarization ticket version");
        cJSON_Delete(root);
        return false;
    }
    cJSON* appPkg = cJSON_GetObjectItem(root, "appPackage");
    if (appPkg == nullptr) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "appPackage not found in notarization ticket");
        cJSON_Delete(root);
        return false;
    }
    cJSON* devId = cJSON_GetObjectItem(appPkg, "developerId");
    cJSON* bName = cJSON_GetObjectItem(appPkg, "bundleName");
    if (!cJSON_IsString(devId) || !cJSON_IsString(bName)) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR,
            "developerId/bundleName not found in appPackage");
        cJSON_Delete(root);
        return false;
    }
    ctx.developerId = cJSON_GetStringValue(devId);
    ctx.bundleName = cJSON_GetStringValue(bName);
    ctx.packageHash = FindHashField(appPkg, ctx.packageHashType);
    if (ctx.packageHash.empty()) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "hash digest not found in appPackage");
        cJSON_Delete(root);
        return false;
    }
    ParseFileHashes(root, ctx.fileHashes);
    cJSON_Delete(root);
    return true;
}

bool TicketValidate::GetProfileFromBlocks(const std::vector<OptionalBlock>& optionBlocks,
    std::string& profileContent)
{
    for (const auto& block : optionBlocks) {
        if (block.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            std::string profileRaw(block.optionalBlockValue.GetBufferPtr(),
                block.optionalBlockValue.GetCapacity());
            if (VerifyHap::GetProfileContent(profileRaw, profileContent) < 0) {
                PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse profile content failed");
                return false;
            }
            return true;
        }
    }
    PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "profile block not found");
    return false;
}

bool TicketValidate::ComputeEntryHash(unzFile zFile, const std::string& filePath,
    TicketHashType hashType, std::string& hashHex)
{
    if (unzLocateFile(zFile, filePath.c_str(), 0) != UNZ_OK) {
        PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR,
            "entry not found: " + filePath);
        return false;
    }
    unz_file_info info;
    if (unzGetCurrentFileInfo(zFile, &info, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "get entry info failed: " + filePath);
        return false;
    }
    if (unzOpenCurrentFile(zFile) != UNZ_OK) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open entry failed: " + filePath);
        return false;
    }
    hashHex = ComputeHashHexStream(zFile, hashType);
    unzCloseCurrentFile(zFile);
    if (hashHex.empty()) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "read entry failed: " + filePath);
        return false;
    }
    return true;
}

bool TicketValidate::VerifySubPackageHashes(const std::string& appFile,
    const std::vector<FileHashEntry>& fileHashes)
{
    if (fileHashes.empty()) {
        return true;
    }
    unzFile zFile = unzOpen(appFile.c_str());
    if (zFile == NULL) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open app file failed: " + appFile);
        return false;
    }
    for (const auto& entry : fileHashes) {
        std::string hashHex;
        if (!ComputeEntryHash(zFile, entry.path, entry.hashType, hashHex)) {
            unzClose(zFile);
            return false;
        }
        if (hashHex != entry.hashValue) {
            PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR, "entry hash mismatch");
            unzClose(zFile);
            return false;
        }
    }
    unzClose(zFile);
    return true;
}

bool TicketValidate::VerifyTicketPkcs7(const std::string& ticketP7b, std::string& ticketJson)
{
    PKCS7Data p7Data;
    if (p7Data.Parse(ticketP7b) < 0) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR,
            "parse notarization ticket pkcs7 failed");
        return false;
    }
    if (p7Data.Verify() < 0) {
        PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR,
            "notarization ticket signature verification failed");
        return false;
    }
    if (p7Data.GetContent(ticketJson) < 0) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR,
            "get notarization ticket content failed");
        return false;
    }
    return true;
}

bool TicketValidate::VerifyPackageHash(const std::string& packageHash, TicketHashType hashType,
    const SignatureInfo& signInfo)
{
    std::string hapSigDer(signInfo.hapSignatureBlock.GetBufferPtr(),
        signInfo.hapSignatureBlock.GetCapacity());
    PKCS7Data p7Data;
    if (p7Data.Parse(hapSigDer) < 0) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse hap signature pkcs7 failed");
        return false;
    }
    std::string authAttrDer;
    if (p7Data.GetAuthenticatedAttributesSetDer(authAttrDer) < 0) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR,
            "get authenticatedAttributes SET DER failed");
        return false;
    }
    std::string hashHex = ComputeHashHex(authAttrDer.data(),
        static_cast<int>(authAttrDer.size()), hashType);
    if (hashHex != packageHash) {
        PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR, "packageHash mismatch");
        return false;
    }
    return true;
}

bool TicketValidate::VerifyProfileAssociation(const ProfileInfo& profileInfo,
    const std::string& devId, const std::string& bundleName)
{
    if (profileInfo.bundleInfo.developerId != devId) {
        PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR,
            "developerId mismatch: profile=" + profileInfo.bundleInfo.developerId +
            ", ticket=" + devId);
        return false;
    }
    if (profileInfo.bundleInfo.bundleName != bundleName) {
        PrintErrorNumberMsg("STAPLE_VERIFY_ERROR", STAPLE_VERIFY_ERROR,
            "bundleName mismatch: profile=" + profileInfo.bundleInfo.bundleName +
            ", ticket=" + bundleName);
        return false;
    }
    return true;
}

bool TicketValidate::ExtractValidateInfo(ValidateContext& ctx)
{
    RandomAccessFile inputFile;
    if (!inputFile.Init(ctx.inFile)) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, ctx.inFile + " init failed");
        return false;
    }
    if (!HapSignerBlockUtils::FindHapSignature(inputFile, ctx.signInfo)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR,
            "find HAP signature in " + ctx.inFile + " failed");
        return false;
    }
    std::string ticketP7b;
    if (!ExtractTicketP7b(ctx.signInfo, ticketP7b)) {
        return false;
    }
    std::string ticketJson;
    if (!VerifyTicketPkcs7(ticketP7b, ticketJson)) {
        return false;
    }
    if (!ParseTicketJson(ticketJson, ctx)) {
        return false;
    }
    std::string profileContent;
    if (!GetProfileFromBlocks(ctx.signInfo.optionBlocks, profileContent)) {
        return false;
    }
    if (ParseProvision(profileContent, ctx.profileInfo) != PROVISION_OK) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse provision failed");
        return false;
    }
    return true;
}

bool TicketValidate::RunValidateChecks(ValidateContext& ctx)
{
    if (!VerifyProfileAssociation(ctx.profileInfo, ctx.developerId, ctx.bundleName)) {
        return false;
    }
    if (!VerifyPackageHash(ctx.packageHash, ctx.packageHashType, ctx.signInfo)) {
        return false;
    }
    return VerifySubPackageHashes(ctx.inFile, ctx.fileHashes);
}

bool TicketValidate::ValidateStaple(Options* options)
{
    ValidateContext ctx;
    ctx.inFile = options->GetString(Options::IN_FILE);
    if (!ExtractValidateInfo(ctx)) {
        return false;
    }
    return RunValidateChecks(ctx);
}

} // namespace SignatureTools
} // namespace OHOS
