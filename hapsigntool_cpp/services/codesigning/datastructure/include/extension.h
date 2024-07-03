﻿/*
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
#ifndef SIGNATRUETOOLS_EXTENSION_H
#define SIGNATRUETOOLS_EXTENSION_H

#include <vector>
#include <string>
#include <cstdint>

#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {

class Extension {
public:
    Extension();
    Extension(int32_t type, int32_t size);
    virtual ~Extension();
    virtual int32_t GetSize();
    virtual std::vector<int8_t> ToByteArray();
    bool IsType(int32_t type);
    static const int32_t EXTENSION_HEADER_SIZE;

private:
    int32_t type;
    int32_t size;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_EXTENSION_H
