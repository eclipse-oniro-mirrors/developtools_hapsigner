/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef SIGNERTOOLS_SERVICE_API_H
#define SIGNERTOOLS_SERVICE_API_H

#include "options.h"

namespace OHOS {
namespace SignatureTools {

class ServiceApi {
public:
    ServiceApi() = default;
    ~ServiceApi() = default;

    virtual bool Sign(Options* params) = 0;
    virtual bool Verify(Options* option) = 0;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNERTOOLS_SERVICE_API_H