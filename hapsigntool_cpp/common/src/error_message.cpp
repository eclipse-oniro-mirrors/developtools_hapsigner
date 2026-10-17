/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "error_message.h"

namespace OHOS {
namespace SignatureTools {

SignToolErrMsg::SignToolErrMsg(const std::string& code, const std::string& description,
                               const std::vector<std::string>& solutions)
    : code(code), description(description), solutions(solutions) {}

std::string SignToolErrMsg::ToString(const std::string& cause) const
{
    std::ostringstream oss;
    oss << "ERROR: " << code << " " << description << std::endl;
    oss << "Error Message: " << cause << std::endl;

    if (!solutions.empty()) {
        oss << "\n* Try the following: " << std::endl;
        for (const auto& s : solutions) {
            oss << " > " << s << std::endl;
        }
    }
    return oss.str();
}

const SignToolErrMsg SignToolErrMsg::UNKNOWN_ERROR = SignToolErrMsg(
    "10010001",
    "Unknown error",
    {});

const SignToolErrMsg SignToolErrMsg::UNSUPPORTED_METHOD = SignToolErrMsg(
    "11011001",
    "Unsupported command method",
    {
        "Please run hap-sign-tool -h to see more help message."
    });

const SignToolErrMsg SignToolErrMsg::PARAM_CHECK_FAILED = SignToolErrMsg(
    "11011002",
    "param is incorrect",
    {});

const SignToolErrMsg SignToolErrMsg::PARAM_NUM_ERROR = SignToolErrMsg(
    "11011003",
    "Check param num failed",
    {
        "Please run hap-sign-tool -h to see more help message."
    });

const SignToolErrMsg SignToolErrMsg::PARAM_VALUE_EMPTY = SignToolErrMsg(
    "11011004",
    "Empty param error",
    {});

const SignToolErrMsg SignToolErrMsg::PARAM_NOT_TRUSTED = SignToolErrMsg(
    "11011005",
    "Param is not trusted",
    {
        "Please run hap-sign-tool -h to see more help message."
    });

const SignToolErrMsg SignToolErrMsg::PARAM_NOT_IN_PAIRS = SignToolErrMsg(
    "11011006",
    "Param {-key value} must in pairs",
    {
        "Please run hap-sign-tool -h to see more help message."
    });

const SignToolErrMsg SignToolErrMsg::PARAM_DUPLICATE = SignToolErrMsg(
    "11011007",
    "Param is duplicated",
    {});

const SignToolErrMsg SignToolErrMsg::PARAM_REQUIRED = SignToolErrMsg(
    "11011008",
    "Missing required param",
    {
        "Please input required param"
    });

const SignToolErrMsg SignToolErrMsg::MISSING_PARAM = SignToolErrMsg(
    "11011008",
    "Check param failed",
    {});

const SignToolErrMsg SignToolErrMsg::LOAD_REMOTE_PLUGIN_FAILED = SignToolErrMsg(
    "11012001",
    "Load remote sign plugin failed",
    {});

const SignToolErrMsg SignToolErrMsg::FILE_NOT_EXIST = SignToolErrMsg(
    "11012002",
    "File not exist",
    {});

const SignToolErrMsg SignToolErrMsg::FILE_WRITE_FAILED = SignToolErrMsg(
    "11012003",
    "Write file failed",
    {});

const SignToolErrMsg SignToolErrMsg::FILE_READ_FAILED = SignToolErrMsg(
    "11012004",
    "Read file failed",
    {});

const SignToolErrMsg SignToolErrMsg::NOT_SUPPORT_FILE = SignToolErrMsg(
    "11012005",
    "Not support file",
    {});

const SignToolErrMsg SignToolErrMsg::FILE_IO_FAILED = SignToolErrMsg(
    "11012006",
    "File IO failed",
    {});

const SignToolErrMsg SignToolErrMsg::CERT_DN_FORMAT_FAILED = SignToolErrMsg(
    "11013001",
    "Check DN format failed",
    {
        "Please check param"
    });

const SignToolErrMsg SignToolErrMsg::CERT_FORMAT_FAILED = SignToolErrMsg(
    "11013002",
    "Certificate format is incorrect, please check your appCertFile parameter.",
    {
        "{-appCertFile} should input a cert chain file, this file is usually suffixed with .cer."
    });

const SignToolErrMsg SignToolErrMsg::GENERATE_CA_FAILED = SignToolErrMsg(
    "11013003",
    "Generate CA failed",
    {});

const SignToolErrMsg SignToolErrMsg::CERT_CHAIN_FORMAT_FAILED = SignToolErrMsg(
    "11013004",
    "Profile cert must be a cert chain",
    {});

const SignToolErrMsg SignToolErrMsg::NO_SUCH_SIGNATURE = SignToolErrMsg(
    "11013005",
    "No such algorithm",
    {});

const SignToolErrMsg SignToolErrMsg::CERT_IO_FAILED = SignToolErrMsg(
    "11013006",
    "Certificate IO failed",
    {});

const SignToolErrMsg SignToolErrMsg::CERTIFICATE_ERROR = SignToolErrMsg(
    "11013007",
    "Certificate check failed",
    {});

const SignToolErrMsg SignToolErrMsg::IO_CSR_ERROR = SignToolErrMsg(
    "11013008",
    "generate csr failed",
    {});

const SignToolErrMsg SignToolErrMsg::KEY_ALIAS_NOT_FOUND = SignToolErrMsg(
    "11014001",
    "Key alias not found",
    {
        "Please check keystore file and keyAlias, ensure keyAlias is exist",
        "Use jdk tool [keytool] check keystore: [keytool -list -keystore xxx.p12]"
    });

const SignToolErrMsg SignToolErrMsg::KEY_ALIAS_EXIST = SignToolErrMsg(
    "11014002",
    "Key alias is exist",
    {
        "Please check keystore file and keyAlias, ensure keyAlias is not exist",
        "Use jdk tool [keytool] check keystore: [keytool -list -keystore xxx.p12]"
    });

const SignToolErrMsg SignToolErrMsg::INIT_KEYSTORE_FAILED = SignToolErrMsg(
    "11014003",
    "Init keystore failed",
    {
        "The key store file does not exist, please check the key store file path.",
        "Incorrect keystore password, please input the correct plaintext password.",
        "The keystore was created by a newer JDK version, please use the same JDK version"
    });

const SignToolErrMsg SignToolErrMsg::INVALID_KEY = SignToolErrMsg(
    "11014004",
    "Invalid Key",
    {});

const SignToolErrMsg SignToolErrMsg::ALGORITHM_NOT_SUPPORT = SignToolErrMsg(
    "11014005",
    "Not support algorithm",
    {});

const SignToolErrMsg SignToolErrMsg::KEYSTORE_ERROR = SignToolErrMsg(
    "11014006",
    "Keystore exception",
    {});

const SignToolErrMsg SignToolErrMsg::KEY_PASSWORD_ERROR = SignToolErrMsg(
    "11014007",
    "Key alias password error",
    {});

const SignToolErrMsg SignToolErrMsg::NO_USABLE_CERT = SignToolErrMsg(
    "11014008",
    "No usable cert found",
    {});

const SignToolErrMsg SignToolErrMsg::SIGNATURE_FAILED = SignToolErrMsg(
    "11015001",
    "Signature failed",
    {});

const SignToolErrMsg SignToolErrMsg::SIGNATURE_NOT_MATCHED = SignToolErrMsg(
    "11015002",
    "Signature not matched!",
    {
        "Please check if the keyAlias private key matches the public key in the certificate",
        "If the certificate is changed, the keyAlias should be replaced synchronously"
    });

const SignToolErrMsg SignToolErrMsg::VERIFY_FAILED = SignToolErrMsg(
    "11015003",
    "Verify signature failed",
    {});

const SignToolErrMsg SignToolErrMsg::VERIFY_PROFILE_FAILED = SignToolErrMsg(
    "11015004",
    "Verify profile failed",
    {});

const SignToolErrMsg SignToolErrMsg::VERIFY_PROFILE_INVALID = SignToolErrMsg(
    "11015005",
    "Verify profile failed",
    {
        "Check if the profile is legal",
        "Maybe Failed during transmission, please download profile again"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_CERT_MATCH_FAILED = SignToolErrMsg(
    "11015005",
    "Profile certificate match failed",
    {
        "Profile include signature certificate info, please ensure it same as your appCertFile",
        "When applying for profile, need to select a certificate, please choose your appCertFile"
    });

const SignToolErrMsg SignToolErrMsg::READ_ZIP_FAILED = SignToolErrMsg(
    "11017001",
    "Read zip file failed",
    {
        "App (or hap/hsp/hnp) use zip format.",
        "Zip file can support a maximum size of 4G and 65535 sub files.",
        "If this value is exceeded, it will be automatically converted to zip64.",
        "Please check if file is zip64 format, or zip formatted correctly."
    });

const SignToolErrMsg SignToolErrMsg::WRITE_ZIP_FAILED = SignToolErrMsg(
    "11017002",
    "Write zip file failed",
    {});

const SignToolErrMsg SignToolErrMsg::ALIGNMENT_ZIP_FAILED = SignToolErrMsg(
    "11017003",
    "Alignment zip file failed",
    {});

const SignToolErrMsg SignToolErrMsg::ZIP_FORMAT_FAILED = SignToolErrMsg(
    "11017004",
    "Zip format failed",
    {});

const SignToolErrMsg SignToolErrMsg::SIGNED_APP_SIZE_INVALID = SignToolErrMsg(
    "11017005",
    "The size of signed application is out of range",
    {
        "The size of application exceeded 4GB after being signed, which is beyond the zip specification.",
        "Please reduce the application package size."
    });

const SignToolErrMsg SignToolErrMsg::HAP_VERIFY_FAILED = SignToolErrMsg(
    "11018001",
    "Verify input HAP failed",
    {});

const SignToolErrMsg SignToolErrMsg::UNSUPPORTED_DISTRIBUTION_TYPE = SignToolErrMsg(
    "11018002",
    "Unsupported application distribution type",
    {});

const SignToolErrMsg SignToolErrMsg::STAPLE_FAILED = SignToolErrMsg(
    "11019001",
    "Staple ticket failed",
    {});

const SignToolErrMsg SignToolErrMsg::STAPLE_VERIFY_FAILED = SignToolErrMsg(
    "11019002",
    "Staple ticket verify failed",
    {});

const SignToolErrMsg SignToolErrMsg::FILE_FORMAT_UNSUPPORTED_ERROR = SignToolErrMsg(
    "11106001",
    "Invalid File Format",
    {});

const SignToolErrMsg SignToolErrMsg::READ_INPUT_STREAM_ERROR = SignToolErrMsg(
    "11110001",
    "Input Stream Read Error",
    {});

const SignToolErrMsg SignToolErrMsg::CERTIFICATES_CONFIGURE_ERROR = SignToolErrMsg(
    "11111001",
    "Certificates Error",
    {
        "Please check whether the certificate is correct"
    });

const SignToolErrMsg SignToolErrMsg::SIGNATURE_VERIFY_FAILED_ERROR = SignToolErrMsg(
    "11111002",
    "Certificates Error",
    {
        "Please check whether the keyAlias is correct"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_TYPE_UNSUPPORTED_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Value of 'type' in profile file should be debug or release"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_TYPE_NOT_EXISTED_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Add 'type' to the profile file"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_BUNDLE_INFO_NOT_EXISTED_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Add 'bundle-info' to the profile file"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_PLUGIN_ID_NOT_EXISTED_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Add 'pluginDistributionIDs' to the profile file"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_APPID_VALUE_TYPE_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Value type of app-identifier should be string"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_PLUGIN_ID_VALUE_TYPE_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Value type of pluginDistributionIDs should be string"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_APPID_VALUE_LENGTH_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Modify to a valid app-identifier in profile file"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_PLUGIN_ID_VALUE_LENGTH_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Modify to a valid pluginDistributionIDs in profile file"
    });

const SignToolErrMsg SignToolErrMsg::PROFILE_JSON_PARSE_ERROR = SignToolErrMsg(
    "11112001",
    "Profile Content Error",
    {
        "Please check whether the profile file is correct"
    });

const SignToolErrMsg SignToolErrMsg::MODULE_JSON_PARSE_ERROR = SignToolErrMsg(
    "11112002",
    "module.json Content Error",
    {
        "Please check whether the module.json is correct"
    });

const SignToolErrMsg SignToolErrMsg::HNP_FILE_DESCRIPTION_ERROR = SignToolErrMsg(
    "11112002",
    "module.json Content Error",
    {
        "Hnp file should be described in module.json"
    });

const SignToolErrMsg SignToolErrMsg::ELF_FILE_HEADER_ERROR = SignToolErrMsg(
    "11112003",
    "Elf File Error",
    {
        "Failed to read the elf file, please check whether the file header information is correct"
    });

const SignToolErrMsg SignToolErrMsg::EXTRACT_HNP_FILE_ERROR = SignToolErrMsg(
    "11112004",
    "File Format Error",
    {
        "Check whether the hnp file is packaged correctly"
    });

const SignToolErrMsg SignToolErrMsg::ALGORITHM_NOT_SUPPORT_ERROR = SignToolErrMsg(
    "11113001",
    "Digest Algorithm Error",
    {
        "Support SHA-256 and SHA-512, if an error occurs, please check the JDK version"
    });

const SignToolErrMsg SignToolErrMsg::CODE_SIGN_INTERNAL_ERROR = SignToolErrMsg(
    "11114001",
    "Code Sign Internal Error",
    {});

const SignToolErrMsg SignToolErrMsg::FILE_4K_ALIGNMENT_ERROR = SignToolErrMsg(
    "11114001",
    "Code Sign Internal Error",
    {});

const SignToolErrMsg SignToolErrMsg::PAGE_INFO_ERROR = SignToolErrMsg(
    "11114001",
    "Code Sign Internal Error",
    {});

} // namespace SignatureTools
} // namespace OHOS
