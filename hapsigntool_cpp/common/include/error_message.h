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
#ifndef SIGNATURETOOLS_ERROR_MESSAGE_H
#define SIGNATURETOOLS_ERROR_MESSAGE_H
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <memory>

namespace OHOS {
namespace SignatureTools {

class SignToolErrMsg {
public:
    SignToolErrMsg(const std::string& code, const std::string& description, const std::vector<std::string>& solutions);
    std::string ToString(const std::string& cause) const;

private:
    std::string code;
    std::string description;
    std::vector<std::string> solutions;

public:
    static const SignToolErrMsg UNKNOWN_ERROR;
    static const SignToolErrMsg UNSUPPORTED_METHOD;
    static const SignToolErrMsg PARAM_CHECK_FAILED;
    static const SignToolErrMsg PARAM_NUM_ERROR;
    static const SignToolErrMsg PARAM_VALUE_EMPTY;
    static const SignToolErrMsg PARAM_NOT_TRUSTED;
    static const SignToolErrMsg PARAM_NOT_IN_PAIRS;
    static const SignToolErrMsg PARAM_DUPLICATE;
    static const SignToolErrMsg PARAM_REQUIRED;
    static const SignToolErrMsg MISSING_PARAM;
    static const SignToolErrMsg LOAD_REMOTE_PLUGIN_FAILED;
    static const SignToolErrMsg FILE_NOT_EXIST;
    static const SignToolErrMsg FILE_WRITE_FAILED;
    static const SignToolErrMsg FILE_READ_FAILED;
    static const SignToolErrMsg NOT_SUPPORT_FILE;
    static const SignToolErrMsg FILE_IO_FAILED;
    static const SignToolErrMsg CERT_DN_FORMAT_FAILED;
    static const SignToolErrMsg CERT_FORMAT_FAILED;
    static const SignToolErrMsg GENERATE_CA_FAILED;
    static const SignToolErrMsg CERT_CHAIN_FORMAT_FAILED;
    static const SignToolErrMsg NO_SUCH_SIGNATURE;
    static const SignToolErrMsg CERT_IO_FAILED;
    static const SignToolErrMsg CERTIFICATE_ERROR;
    static const SignToolErrMsg IO_CSR_ERROR;
    static const SignToolErrMsg KEY_ALIAS_NOT_FOUND;
    static const SignToolErrMsg KEY_ALIAS_EXIST;
    static const SignToolErrMsg INIT_KEYSTORE_FAILED;
    static const SignToolErrMsg INVALID_KEY;
    static const SignToolErrMsg ALGORITHM_NOT_SUPPORT;
    static const SignToolErrMsg KEYSTORE_ERROR;
    static const SignToolErrMsg KEY_PASSWORD_ERROR;
    static const SignToolErrMsg NO_USABLE_CERT;
    static const SignToolErrMsg SIGNATURE_FAILED;
    static const SignToolErrMsg SIGNATURE_NOT_MATCHED;
    static const SignToolErrMsg VERIFY_FAILED;
    static const SignToolErrMsg VERIFY_PROFILE_FAILED;
    static const SignToolErrMsg VERIFY_PROFILE_INVALID;
    static const SignToolErrMsg PROFILE_CERT_MATCH_FAILED;
    static const SignToolErrMsg READ_ZIP_FAILED;
    static const SignToolErrMsg WRITE_ZIP_FAILED;
    static const SignToolErrMsg ALIGNMENT_ZIP_FAILED;
    static const SignToolErrMsg ZIP_FORMAT_FAILED;
    static const SignToolErrMsg SIGNED_APP_SIZE_INVALID;
    static const SignToolErrMsg HAP_VERIFY_FAILED;
    static const SignToolErrMsg UNSUPPORTED_DISTRIBUTION_TYPE;
    static const SignToolErrMsg FILE_FORMAT_UNSUPPORTED_ERROR;
    static const SignToolErrMsg READ_INPUT_STREAM_ERROR;
    static const SignToolErrMsg CERTIFICATES_CONFIGURE_ERROR;
    static const SignToolErrMsg SIGNATURE_VERIFY_FAILED_ERROR;
    static const SignToolErrMsg PROFILE_TYPE_UNSUPPORTED_ERROR;
    static const SignToolErrMsg PROFILE_TYPE_NOT_EXISTED_ERROR;
    static const SignToolErrMsg PROFILE_BUNDLE_INFO_NOT_EXISTED_ERROR;
    static const SignToolErrMsg PROFILE_PLUGIN_ID_NOT_EXISTED_ERROR;
    static const SignToolErrMsg PROFILE_APPID_VALUE_TYPE_ERROR;
    static const SignToolErrMsg PROFILE_PLUGIN_ID_VALUE_TYPE_ERROR;
    static const SignToolErrMsg PROFILE_APPID_VALUE_LENGTH_ERROR;
    static const SignToolErrMsg PROFILE_PLUGIN_ID_VALUE_LENGTH_ERROR;
    static const SignToolErrMsg PROFILE_JSON_PARSE_ERROR;
    static const SignToolErrMsg MODULE_JSON_PARSE_ERROR;
    static const SignToolErrMsg HNP_FILE_DESCRIPTION_ERROR;
    static const SignToolErrMsg ELF_FILE_HEADER_ERROR;
    static const SignToolErrMsg EXTRACT_HNP_FILE_ERROR;
    static const SignToolErrMsg ALGORITHM_NOT_SUPPORT_ERROR;
    static const SignToolErrMsg CODE_SIGN_INTERNAL_ERROR;
    static const SignToolErrMsg FILE_4K_ALIGNMENT_ERROR;
    static const SignToolErrMsg PAGE_INFO_ERROR;
    static const SignToolErrMsg STAPLE_FAILED;
    static const SignToolErrMsg STAPLE_VERIFY_FAILED;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_ERROR_MESSAGE_H
