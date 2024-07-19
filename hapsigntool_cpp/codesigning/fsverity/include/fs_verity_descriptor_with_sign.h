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
#ifndef SIGNATURETOOLS_FSVERITY_DESCRIPTOR_WITH_SIGN_H
#define SIGNATURETOOLS_FSVERITY_DESCRIPTOR_WITH_SIGN_H

#include <vector>
#include <string>

#include "fs_verity_descriptor.h"

namespace OHOS {
namespace SignatureTools {
class FsVerityDescriptorWithSign {
public:
    static constexpr int32_t INTEGER_BYTES = 4;

public:
    FsVerityDescriptorWithSign();
    FsVerityDescriptorWithSign(FsVerityDescriptor fsVerityDescriptor, std::vector<int8_t> &signature);
    FsVerityDescriptorWithSign(int32_t type, int32_t length, FsVerityDescriptor fsVerityDescriptor,
                               std::vector<int8_t> &signature);
    int32_t Size();
    void ToByteArray(std::vector<int8_t> &ret);
    FsVerityDescriptor GetFsVerityDescriptor();
    std::vector<int8_t>& GetSignature();

private:
    int32_t type = FsVerityDescriptor::FS_VERITY_DESCRIPTOR_TYPE;;
    int32_t length;
    FsVerityDescriptor fsVerityDescriptor;
    std::vector<int8_t> signature;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_FSVERITY_DIGEST_H