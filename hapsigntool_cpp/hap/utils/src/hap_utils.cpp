/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "cJSON.h"
#include "contrib/minizip/unzip.h"
#include "profile_verify.h"
#include "hap_utils.h"

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

std::vector<std::string> HapUtils::GetSkillNamesFromJson(const std::string& moduleJson)
{
    std::vector<std::string> skillNames;
    if (moduleJson.empty()) {
        return skillNames;
    }
    cJSON* root = cJSON_ParseWithOpts(moduleJson.c_str(), nullptr, 1);
    if (root == nullptr) {
        SIGNATURE_TOOLS_LOGE("Failed to parse module.json");
        return skillNames;
    }
    cJSON* moduleObj = cJSON_GetObjectItemCaseSensitive(root, "module");
    if (moduleObj == nullptr || !cJSON_IsObject(moduleObj)) {
        SIGNATURE_TOOLS_LOGE("module.json has no module object");
        cJSON_Delete(root);
        return skillNames;
    }
    cJSON* skillsArray = cJSON_GetObjectItemCaseSensitive(moduleObj, "skillProfiles");
    if (skillsArray == nullptr || !cJSON_IsArray(skillsArray)) {
        SIGNATURE_TOOLS_LOGI("module.json has no skillProfiles key or skillProfiles value is not an array");
        cJSON_Delete(root);
        return skillNames;
    }
    cJSON* skillItem = nullptr;
    cJSON_ArrayForEach(skillItem, skillsArray) {
        if (!cJSON_IsObject(skillItem)) {
            continue;
        }
        cJSON* nameObj = cJSON_GetObjectItemCaseSensitive(skillItem, "name");
        if (nameObj != nullptr && cJSON_IsString(nameObj) && nameObj->valuestring != nullptr) {
            std::string name(nameObj->valuestring);
            if (!name.empty()) {
                skillNames.push_back(name);
            }
        }
    }
    cJSON_Delete(root);
    return skillNames;
}

bool HapUtils::GetModuleContentFromHap(const std::string& hapPath, std::string& moduleContent)
{
    moduleContent.clear();
    unzFile zFile = unzOpen(hapPath.c_str());
    if (zFile == nullptr) {
        SIGNATURE_TOOLS_LOGE("Failed to open HAP file: %s", hapPath.c_str());
        return false;
    }
    if (unzLocateFile(zFile, "module.json", 0) != UNZ_OK) {
        SIGNATURE_TOOLS_LOGI("module.json not found in HAP");
        unzClose(zFile);
        return false;
    }
    char fileNameBuffer[512];
    unz_file_info zFileInfo;
    if (unzGetCurrentFileInfo(zFile, &zFileInfo, fileNameBuffer, sizeof(fileNameBuffer), nullptr, 0, nullptr, 0)
        != UNZ_OK) {
        SIGNATURE_TOOLS_LOGE("Failed to get file info for module.json");
        unzClose(zFile);
        return false;
    }
    if (unzOpenCurrentFile(zFile) != UNZ_OK) {
        SIGNATURE_TOOLS_LOGE("Failed to open module.json in HAP");
        unzClose(zFile);
        return false;
    }
    std::vector<char> buffer(zFileInfo.uncompressed_size + 1);
    int readSize = unzReadCurrentFile(zFile, buffer.data(), static_cast<unsigned>(zFileInfo.uncompressed_size));
    unzCloseCurrentFile(zFile);
    unzClose(zFile);
    if (readSize <= 0) {
        SIGNATURE_TOOLS_LOGE("Failed to read module.json from HAP");
        return false;
    }
    buffer[readSize] = '\0';
    moduleContent = std::string(buffer.data(), readSize);
    return true;
}

} // namespace SignatureTools
} // namespace OHOS
