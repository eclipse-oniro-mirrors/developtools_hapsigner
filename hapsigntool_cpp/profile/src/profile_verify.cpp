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

#include <algorithm>
#include <map>

#include "cJSON.h"
#include "signature_tools_log.h"
#include "signature_tools_errno.h"
#include "profile_verify.h"

using namespace std;

namespace {
const string KEY_VERSION_CODE = "version-code";
const string KEY_VERSION_NAME = "version-name";
const string KEY_UUID = "uuid";
const string KEY_TYPE = "type";
const string KEY_APP_DIST_TYPE = "app-distribution-type";
const string KEY_BUNDLE_INFO = "bundle-info";
const string KEY_DEVELOPER_ID = "developer-id";
const string KEY_DEVELOPMENT_CERTIFICATE = "development-certificate";
const string KEY_DISTRIBUTION_CERTIFICATE = "distribution-certificate";
const string KEY_BUNDLE_NAME = "bundle-name";
const string KEY_APL = "apl";
const string KEY_APP_FEATURE = "app-feature";
const string KEY_ACLS = "acls";
const string KEY_ALLOWED_ACLS = "allowed-acls";
const string KEY_PERMISSIONS = "permissions";
const string KEY_DATA_GROUP_IDS = "data-group-ids";
const string KEY_RESTRICTED_PERMISSIONS = "restricted-permissions";
const string KEY_RESTRICTED_CAPABILITIES = "restricted-capabilities";
const string KEY_DEBUG_INFO = "debug-info";
const string KEY_DEVICE_ID_TYPE = "device-id-type";
const string KEY_DEVICE_IDS = "device-ids";
const string KEY_ISSUER = "issuer";
const string KEY_APP_PRIVILEGE_CAPABILITIES = "app-privilege-capabilities";
const string KEY_APP_SERVICE_CAPABILITIES = "app-service-capabilities";
const string VALUE_TYPE_RELEASE = "release";
const string VALUE_TYPE_DEBUG = "debug";
const string VALUE_DIST_TYPE_APP_GALLERY = "app_gallery";
const string VALUE_DIST_TYPE_ENTERPRISE = "enterprise";
const string VALUE_DIST_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const string VALUE_DIST_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const string VALUE_DIST_TYPE_OS_INTEGRATION = "os_integration";
const string VALUE_DIST_TYPE_CROWDTESTING = "crowdtesting";
const string VALUE_DEVICE_ID_TYPE_UDID = "udid";
const string VALUE_VALIDITY = "validity";
const string VALUE_NOT_BEFORE = "not-before";
const string VALUE_NOT_AFTER = "not-after";
// reserved field
const string KEY_BASEAPP_INFO = "baseapp-info";
const string KEY_PACKAGE_NAME = "package-name";
const string KEY_PACKAGE_CERT = "package-cert";
const string KEY_APP_IDENTIFIER = "app-identifier";
const string GENERIC_BUNDLE_NAME = ".*";

inline void GetStringIfExist(const cJSON* obj, const string& key, string& out)
{
    cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (item != nullptr && cJSON_IsString(item)) {
        out = item->valuestring;
    }
}

inline void GetInt32IfExist(const cJSON* obj, const string& key, int32_t& out)
{
    cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (item != nullptr && cJSON_IsNumber(item)) {
        out = static_cast<int32_t>(item->valueint);
    }
}

inline void GetInt64IfExist(const cJSON* obj, const string& key, int64_t& out)
{
    cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (item != nullptr && cJSON_IsNumber(item)) {
        out = static_cast<int64_t>(item->valueint);
    }
}

inline void GetStringArrayIfExist(const cJSON* obj, const string& key, vector<string>& out)
{
    cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (item != nullptr && cJSON_IsArray(item)) {
        cJSON* arrayItem = nullptr;
        cJSON_ArrayForEach(arrayItem, item) {
            if (cJSON_IsString(arrayItem)) {
                out.push_back(arrayItem->valuestring);
            }
        }
    }
}
} // namespace

namespace OHOS {
namespace SignatureTools {
const std::map<std::string, int32_t> distTypeMap = {
    {VALUE_DIST_TYPE_APP_GALLERY, AppDistType::APP_GALLERY},
    {VALUE_DIST_TYPE_ENTERPRISE, AppDistType::ENTERPRISE},
    {VALUE_DIST_TYPE_ENTERPRISE_NORMAL, AppDistType::ENTERPRISE_NORMAL},
    {VALUE_DIST_TYPE_ENTERPRISE_MDM, AppDistType::ENTERPRISE_MDM},
    {VALUE_DIST_TYPE_OS_INTEGRATION, AppDistType::OS_INTEGRATION},
    {VALUE_DIST_TYPE_CROWDTESTING, AppDistType::CROWDTESTING}
};

void ParseType(const cJSON* obj, ProfileInfo& out)
{
    string type;
    GetStringIfExist(obj, KEY_TYPE, type);
    /* If not release, then it's debug */
    if (type == VALUE_TYPE_RELEASE)
        out.type = RELEASE;
    else if (type == VALUE_TYPE_DEBUG)
        out.type = DEBUG;
    else out.type = NONE_PROVISION_TYPE;
}

void ParseAppDistType(const cJSON* obj, ProfileInfo& out)
{
    string distType;
    GetStringIfExist(obj, KEY_APP_DIST_TYPE, distType);
    auto ite = distTypeMap.find(distType);
    if (ite != distTypeMap.end()) {
        out.distributionType = static_cast<AppDistType>(distTypeMap.at(distType));
        return;
    }
    out.distributionType = AppDistType::NONE_TYPE;
}

void ParseBundleInfo(const cJSON* obj, ProfileInfo& out)
{
    const cJSON* bundleInfo = cJSON_GetObjectItemCaseSensitive(obj, KEY_BUNDLE_INFO.c_str());
    if (bundleInfo == nullptr || !cJSON_IsObject(bundleInfo)) {
        return;
    }
    GetStringIfExist(bundleInfo, KEY_DEVELOPER_ID, out.bundleInfo.developerId);
    GetStringIfExist(bundleInfo, KEY_DEVELOPMENT_CERTIFICATE,
                     out.bundleInfo.developmentCertificate);
    GetStringIfExist(bundleInfo, KEY_DISTRIBUTION_CERTIFICATE,
                     out.bundleInfo.distributionCertificate);
    GetStringIfExist(bundleInfo, KEY_BUNDLE_NAME, out.bundleInfo.bundleName);
    GetStringIfExist(bundleInfo, KEY_APL, out.bundleInfo.apl);
    GetStringIfExist(bundleInfo, KEY_APP_FEATURE, out.bundleInfo.appFeature);
    GetStringIfExist(bundleInfo, KEY_APP_IDENTIFIER, out.bundleInfo.appIdentifier);
    GetStringArrayIfExist(bundleInfo, KEY_DATA_GROUP_IDS, out.bundleInfo.dataGroupIds);
}

void ParseAcls(const cJSON* obj, ProfileInfo& out)
{
    const cJSON* acls = cJSON_GetObjectItemCaseSensitive(obj, KEY_ACLS.c_str());
    if (acls == nullptr || !cJSON_IsObject(acls)) {
        return;
    }
    GetStringArrayIfExist(acls, KEY_ALLOWED_ACLS, out.acls.allowedAcls);
}

void ParsePermissions(const cJSON* obj, ProfileInfo& out)
{
    const cJSON* permissions = cJSON_GetObjectItemCaseSensitive(obj, KEY_PERMISSIONS.c_str());
    if (permissions == nullptr || !cJSON_IsObject(permissions)) {
        return;
    }
    GetStringArrayIfExist(permissions, KEY_RESTRICTED_PERMISSIONS,
                          out.permissions.restrictedPermissions);
    GetStringArrayIfExist(permissions, KEY_RESTRICTED_CAPABILITIES,
                          out.permissions.restrictedCapabilities);
}

void ParseDebugInfo(const cJSON* obj, ProfileInfo& out)
{
    const cJSON* debugInfo = cJSON_GetObjectItemCaseSensitive(obj, KEY_DEBUG_INFO.c_str());
    if (debugInfo == nullptr || !cJSON_IsObject(debugInfo)) {
        return;
    }
    GetStringIfExist(debugInfo, KEY_DEVICE_ID_TYPE, out.debugInfo.deviceIdType);
    GetStringArrayIfExist(debugInfo, KEY_DEVICE_IDS, out.debugInfo.deviceIds);
}

void ParseValidity(const cJSON* obj, Validity& out)
{
    const cJSON* validity = cJSON_GetObjectItemCaseSensitive(obj, VALUE_VALIDITY.c_str());
    if (validity == nullptr || !cJSON_IsObject(validity)) {
        return;
    }
    GetInt64IfExist(validity, VALUE_NOT_BEFORE, out.notBefore);
    GetInt64IfExist(validity, VALUE_NOT_AFTER, out.notAfter);
}

void ParseMetadata(const cJSON* obj, ProfileInfo& out)
{
    const cJSON* baseAppInfo = cJSON_GetObjectItemCaseSensitive(obj, KEY_BASEAPP_INFO.c_str());
    if (baseAppInfo == nullptr || !cJSON_IsObject(baseAppInfo)) {
        return;
    }
    Metadata metadata;
    metadata.name = KEY_PACKAGE_NAME;
    GetStringIfExist(baseAppInfo, KEY_PACKAGE_NAME, metadata.value);
    out.metadatas.emplace_back(metadata);
    metadata.name = KEY_PACKAGE_CERT;
    GetStringIfExist(baseAppInfo, KEY_PACKAGE_CERT, metadata.value);
    out.metadatas.emplace_back(metadata);
}

void from_json(const cJSON* obj, ProfileInfo& out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    GetInt32IfExist(obj, KEY_VERSION_CODE, out.versionCode);
    GetStringIfExist(obj, KEY_VERSION_NAME, out.versionName);
    GetStringIfExist(obj, KEY_UUID, out.uuid);
    ParseType(obj, out);
    ParseAppDistType(obj, out);
    ParseBundleInfo(obj, out);
    ParseAcls(obj, out);
    ParsePermissions(obj, out);
    ParseDebugInfo(obj, out);
    GetStringIfExist(obj, KEY_ISSUER, out.issuer);
    GetStringArrayIfExist(obj, KEY_APP_PRIVILEGE_CAPABILITIES, out.appPrivilegeCapabilities);
    ParseValidity(obj, out.validity);
    ParseMetadata(obj, out);
    GetStringIfExist(obj, KEY_APP_SERVICE_CAPABILITIES, out.appServiceCapabilities);
}

AppProvisionVerifyResult ReturnIfStringIsEmpty(const std::string& str, const std::string& errMsg)
{
    if (str.empty()) {
        PrintErrorNumberMsg("PROVISION_INVALID_ERROR", PROVISION_INVALID_ERROR, errMsg);
        return PROVISION_INVALID;
    }
    return PROVISION_OK;
}

static AppProvisionVerifyResult CheckProfileValidType(const ProfileInfo& info)
{
    if (info.type == ProvisionType::DEBUG) {
        if (ReturnIfStringIsEmpty(info.bundleInfo.developmentCertificate,
                                  "Tag development-certificate is empty.") != PROVISION_OK) {
            return PROVISION_INVALID;
        }
    } else if (info.type == ProvisionType::RELEASE) {
        if (ReturnIfStringIsEmpty(info.bundleInfo.distributionCertificate,
                                  "Tag distribution-certificate is empty.") != PROVISION_OK) {
            return PROVISION_INVALID;
        }
    } else {
        PrintErrorNumberMsg("PROVISION_INVALID_ERROR", PROVISION_INVALID_ERROR,
                            "The type field in the profile file is incorrect");
        return PROVISION_INVALID;
    }
    return PROVISION_OK;
}

AppProvisionVerifyResult ParseProvision(const string& appProvision, ProfileInfo& info)
{
    if (ParseProfile(appProvision, info) != PROVISION_OK) {
        return PROVISION_INVALID;
    }

    if (CheckProfileValidType(info) != PROVISION_OK) {
        return PROVISION_INVALID;
    }
    return PROVISION_OK;
}

AppProvisionVerifyResult ParseAndVerify(const string& appProvision, ProfileInfo& info)
{
    SIGNATURE_TOOLS_LOGD("Enter HarmonyAppProvision Verify");
    AppProvisionVerifyResult ret = ParseProvision(appProvision, info);
    if (ret != PROVISION_OK) {
        return ret;
    }
    SIGNATURE_TOOLS_LOGD("Leave HarmonyAppProvision Verify");
    return PROVISION_OK;
}

AppProvisionVerifyResult ParseProfile(const std::string& appProvision, ProfileInfo& info)
{
    cJSON* obj = cJSON_ParseWithOpts(appProvision.c_str(), nullptr, 1);
    if (obj == nullptr) {
        std::string errStr = "JSON is invalid or empty, parse provision failed, json: " + appProvision;
        PrintErrorNumberMsg("PROVISION_INVALID_ERROR", PROVISION_INVALID_ERROR, errStr.c_str());
        return PROVISION_INVALID;
    }
    if (!(cJSON_IsObject(obj) || cJSON_IsArray(obj))) {
        std::string errStr = "invalid json object type, must be object or array, json: " + appProvision;
        PrintErrorNumberMsg("PROVISION_INVALID_ERROR", PROVISION_INVALID_ERROR, errStr.c_str());
        cJSON_Delete(obj);
        return PROVISION_INVALID;
    }
    from_json(obj, info);
    cJSON_Delete(obj);
    return PROVISION_OK;
}
} // namespace SignatureTools
} // namespace OHOS