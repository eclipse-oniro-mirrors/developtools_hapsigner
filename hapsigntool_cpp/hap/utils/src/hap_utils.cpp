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

#include <fstream>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <vector>

#include "securec.h"
#include "profile_verify.h"
#include "hap_utils.h"
#include "constant.h"
#include "cJSON.h"
#include <contrib/minizip/unzip.h>

namespace OHOS {
namespace SignatureTools {
    
const std::vector<int8_t> HapUtils::HAP_SIGNING_BLOCK_MAGIC_V2 =
    std::vector<int8_t>{ 0x48, 0x41, 0x50, 0x20, 0x53, 0x69, 0x67, 0x20, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32 };
const std::vector<int8_t> HapUtils::HAP_SIGNING_BLOCK_MAGIC_V3 =
    std::vector<int8_t>{ 0x3c, 0x68, 0x61, 0x70, 0x20, 0x73, 0x69, 0x67, 0x6e,
    0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x3e };
const std::vector<int8_t> HapUtils::PERMISSION_SIGN_MAGIC =
    std::vector<int8_t>{ 0x7d, 0x6a, 0x03, 0x93, 0x0f, 0x45, 0xe2, 0x28 };
const std::string HapUtils::HEX_CHAR_ARRAY = "0123456789ABCDEF";
const std::string HapUtils::HAP_DEBUG_OWNER_ID = "DEBUG_LIB_ID";
const std::string HapUtils::HAP_SHARED_OWNER_ID = "SHARED_LIB_ID";
std::set<int> HapUtils::HAP_SIGNATURE_OPTIONAL_BLOCK_IDS;

HapUtils::StaticConstructor::StaticConstructor()
{
    HAP_SIGNATURE_OPTIONAL_BLOCK_IDS.insert(HAP_PROOF_OF_ROTATION_BLOCK_ID);
    HAP_SIGNATURE_OPTIONAL_BLOCK_IDS.insert(HAP_PROFILE_BLOCK_ID);
    HAP_SIGNATURE_OPTIONAL_BLOCK_IDS.insert(HAP_PROPERTY_BLOCK_ID);
}

HapUtils::StaticConstructor HapUtils::staticConstructor;

std::string HapUtils::GetAppIdentifier(const std::string& profileContent)
{
    std::pair<std::string, std::string> resultPair = ParseAppIdentifier(profileContent);

    std::string ownerID = resultPair.first;
    std::string profileType = resultPair.second;

    if (profileType == "debug") {
        return HAP_DEBUG_OWNER_ID;
    } else if (profileType == "release") {
        return ownerID;
    } else {
        return "";
    }
}

std::pair<std::string, std::string> HapUtils::ParseAppIdentifier(const std::string& profileContent)
{
    std::string ownerID;
    std::string profileType;

    ProfileInfo provisionInfo;
    ParseProfile(profileContent, provisionInfo);

    if (DEBUG == provisionInfo.type) {
        profileType = "debug";
    } else {
        profileType = "release";
    }

    BundleInfo bundleInfo = provisionInfo.bundleInfo;

    if (!bundleInfo.appIdentifier.empty()) {
        ownerID = bundleInfo.appIdentifier;
    }

    return std::pair(ownerID, profileType);
}

std::vector<int8_t> HapUtils::GetHapSigningBlockMagic(int compatibleVersion)
{
    if (compatibleVersion >= MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3) {
        return HAP_SIGNING_BLOCK_MAGIC_V3;
    }
    return HAP_SIGNING_BLOCK_MAGIC_V2;
}

std::vector<int8_t> HapUtils::GetHapSigningBlockMagicV3()
{
    return HAP_SIGNING_BLOCK_MAGIC_V3;
}

const std::vector<int8_t>& HapUtils::GetPermissionSignMagic()
{
    return PERMISSION_SIGN_MAGIC;
}

int HapUtils::GetHapSigningBlockVersion(int compatibleVersion)
{
    if (compatibleVersion >= MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3) {
        return HAP_SIGN_SCHEME_V3_BLOCK_VERSION;
    }
    return HAP_SIGN_SCHEME_V2_BLOCK_VERSION;
}

bool HapUtils::ReadFileToByteBuffer(const std::string& file, ByteBuffer& buffer)
{
    std::string ret;
    if (FileUtils::ReadFile(file, ret) < 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, file + " not exist or can not read!");
        return false;
    }
    buffer.SetCapacity(static_cast<int32_t>(ret.size()));
    buffer.PutData(ret.data(), ret.size());
    return true;
}

std::string HapUtils::GetPublicHnpOwnerId(const std::string& profileContent)
{
    std::string publicOwnerID;
    if (profileContent.empty()) {
        return publicOwnerID;
    }

    cJSON* root = cJSON_Parse(profileContent.c_str());
    if (root == nullptr) {
        return publicOwnerID;
    }
    cJSON* typeNode = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (typeNode != nullptr && cJSON_IsString(typeNode) &&
        typeNode->valuestring != nullptr) {
        std::string profileType = typeNode->valuestring;
        if (profileType == "debug") {
            publicOwnerID = HAP_DEBUG_OWNER_ID;
        } else if (profileType == "release") {
            publicOwnerID = HAP_SHARED_OWNER_ID;
        }
    }
    cJSON_Delete(root);
    return publicOwnerID;
}

std::string HapUtils::ParseHnpPath(const std::string& path)
{
    if (path.empty()) {
        return "";
    }
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(path);
    while (std::getline(tokenStream, token, '/')) {
        tokens.push_back(token);
    }
    while (!tokens.empty() && tokens.back().empty()) {
        tokens.pop_back();
    }
    if (tokens.size() < HNP_MIN_TOKENS) {
        return "";
    }
    std::string result;
    for (size_t i = HNP_MIN_TOKENS - 1; i < tokens.size(); ++i) {
        if (i > (HNP_MIN_TOKENS - 1)) {
            result += "/";
        }
        result += tokens[i];
    }
    return result;
}

bool HapUtils::ParseHnpPackages(const std::string& moduleContent,
    std::unordered_map<std::string, std::string>& hnpNameMap)
{
    cJSON* root = cJSON_Parse(moduleContent.c_str());
    if (root == nullptr) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse module.json failed.");
        return false;
    }
    cJSON* moduleObj = cJSON_GetObjectItemCaseSensitive(root, "module");
    if (moduleObj == nullptr || !cJSON_IsObject(moduleObj)) {
        cJSON_Delete(root);
        return true;
    }
    cJSON* hnpArr = cJSON_GetObjectItemCaseSensitive(moduleObj, "hnpPackages");
    if (hnpArr == nullptr || !cJSON_IsArray(hnpArr) || cJSON_GetArraySize(hnpArr) == 0) {
        cJSON_Delete(root);
        return true;
    }
    cJSON* hnpItem = nullptr;
    cJSON_ArrayForEach(hnpItem, hnpArr) {
        cJSON* pkgName = cJSON_GetObjectItemCaseSensitive(hnpItem, "package");
        if (pkgName == nullptr || !cJSON_IsString(pkgName) ||
            pkgName->valuestring == nullptr || pkgName->valuestring[0] == '\0') {
            continue;
        }
        std::string name = pkgName->valuestring;
        hnpNameMap[name] = HNP_PRIVATE_TYPE;
        cJSON* typeNode = cJSON_GetObjectItemCaseSensitive(hnpItem, "type");
        if (typeNode != nullptr && cJSON_IsString(typeNode) &&
            typeNode->valuestring != nullptr && typeNode->valuestring[0] != '\0') {
            hnpNameMap[name] = typeNode->valuestring;
        }
    }
    cJSON_Delete(root);
    return true;
}

bool HapUtils::GetHnpsFromJson(const std::string& hapFile,
                               std::unordered_map<std::string, std::string>& hnpNameMap)
{
    unzFile zFile = unzOpen(hapFile.c_str());
    if (zFile == nullptr) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open hap file: " + hapFile + " failed.");
        return false;
    }
    if (unzLocateFile(zFile, MODULE_JSON_FILE.c_str(), 0) != UNZ_OK) {
        unzClose(zFile);
        return true;
    }
    if (unzOpenCurrentFile(zFile) != UNZ_OK) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open module.json in hap failed.");
        unzClose(zFile);
        return false;
    }
    std::string moduleContent;
    char readBuffer[4096] = { 0 };
    int readSize = 0;
    do {
        if (memset_s(readBuffer, sizeof(readBuffer), 0, sizeof(readBuffer)) != EOK) {
            unzCloseCurrentFile(zFile);
            unzClose(zFile);
            return false;
        }
        readSize = unzReadCurrentFile(zFile, readBuffer, sizeof(readBuffer));
        if (readSize > 0) {
            moduleContent.append(readBuffer, readSize);
        }
    } while (readSize > 0);
    unzCloseCurrentFile(zFile);
    unzClose(zFile);
    return ParseHnpPackages(moduleContent, hnpNameMap);
}

} // namespace SignatureTools
} // namespace OHOS
