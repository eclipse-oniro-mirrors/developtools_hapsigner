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

#ifndef SIGNATRUETOOLS_CMD_UTIL_H
#define SIGNATRUETOOLS_CMD_UTIL_H

#include <string>
#include <vector>
#include <list>
#include <regex>
#include <assert.h>
#include <algorithm>

#include "params.h"
#include "params_trust_list.h"
#include "sign_tool_service_impl.h"
#include "signature_tools_log.h"
#include "verify_hap_openssl_utils.h"

namespace OHOS {
namespace SignatureTools {
class CmdUtil final {
public:
    static bool Convert2Params(char** args, size_t size, const ParamsSharedPtr& param);
    static bool JudgeAlgType(const std::string& keyAlg);
    static bool JudgeSize(const int size);
    static bool JudgeSignAlgType(const std::string& signAlg);
    static bool VerifyType(const std::string& inputType);
    static bool VerifyTypes(const std::string& inputType);
    static bool VerifyType(const std::string& inputtype, const std::string& supportTypes);
    static bool String2Bool(Options* options, const std::string& option);
    static constexpr int ARGS_MIN_LEN = 2;

private:
    static int GetCommandParameterKey(const char strChar, std::string& strChars,
                                    std::vector<std::string>& trustList, std::string& keyStandBy);
    static bool ValidAndPutParam(ParamsSharedPtr params, const std::string& key, char* value);
    static const std::regex INTEGER_PATTERN;
};
} // namespace SignatureTools
} // namespace OHOS
#endif
