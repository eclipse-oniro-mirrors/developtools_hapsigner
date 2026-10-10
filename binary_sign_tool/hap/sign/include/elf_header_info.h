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

#ifndef SIGNATURETOOLS_ELF_HEADER_INFO_H
#define SIGNATURETOOLS_ELF_HEADER_INFO_H

#include <cstdint>
#include <elfio.hpp>

namespace OHOS {
namespace SignatureTools {

struct ElfHeaderInfo {
    unsigned char fileClass = 0;
    unsigned char encoding = 0;
    ELFIO::Elf_Half sectionEntrySize = 0;
    ELFIO::Elf_Half sectionNameStrIndex = 0;
    ELFIO::Elf64_Off shtOff = 0;
    ELFIO::Elf_Half shNum = 0;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATURETOOLS_ELF_HEADER_INFO_H
