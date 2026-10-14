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
#ifndef SIGNATURETOOLS_PAGE_INFO_EXTENSION_H
#define SIGNATURETOOLS_PAGE_INFO_EXTENSION_H

#include <vector>
#include <cstdint>
#include <string>

#include "extension.h"

namespace OHOS {
namespace SignatureTools {

class PageInfoExtension : public Extension {
public:
    static const int32_t PAGE_INFO_INLINED = 0x2;
    static const int32_t PAGE_INFO_EXTENSION_DATA_SIZE_WITHOUT_SIGN = 24;
    static const int32_t DEFAULT_UNIT_SIZE = 4;

    PageInfoExtension(int64_t mapOffset, int64_t mapSize);
    ~PageInfoExtension() override = default;

    int32_t GetSize() override;
    void ToByteArray(std::vector<int8_t>& ret) override;
    void SetSignature(const std::vector<int8_t>& signature);
    static PageInfoExtension* FromByteArray(std::vector<int8_t>& data);
    std::string ToString() const;

    int64_t GetMapOffset() { return mapOffset; }
    int64_t GetMapSize() { return mapSize; }
    int8_t GetUnitSize() { return unitSize; }
    std::vector<int8_t> GetSignature() { return signature; }

private:
    int64_t mapOffset;
    int64_t mapSize;
    int8_t unitSize;
    int8_t reserved[3];
    int32_t signSize;
    std::vector<int8_t> signature;
    std::vector<int8_t> zeroPadding;
};

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_PAGE_INFO_EXTENSION_H
