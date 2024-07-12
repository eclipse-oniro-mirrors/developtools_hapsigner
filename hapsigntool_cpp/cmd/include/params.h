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

#ifndef SIGNATRUETOOLS_PARAMS_H
#define SIGNATRUETOOLS_PARAMS_H

#include <string>
#include <variant>
#include <iostream>
#include <memory>
#include <unordered_set>
#include <vector>

#include "options.h"
#include "signature_algorithm_helper.h"
#include "param_constants.h"

namespace OHOS {
namespace SignatureTools {
class Params {
public:
    static std::unordered_set<std::string> InitParamField(const std::vector<std::string>& paramFields);
    static bool GetSignatureAlgorithm(const std::string& signatureAlgorithm, SignatureAlgorithmHelper& out);
    Params() = default;
    virtual ~Params() = default;
    virtual std::string GetMethod();
    virtual void SetMethod(const std::string& method);
    virtual Options* GetOptions();

private:
    std::shared_ptr<Options> options = std::make_shared<Options>();

private:
    std::string method;
};

using ParamsSharedPtr = std::shared_ptr<Params>;

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_PARAMS_H
