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

#ifndef SIGNATURETOOLS_ELF_SIGN_WRITER_H
#define SIGNATURETOOLS_ELF_SIGN_WRITER_H

#include <cstdint>
#include <string>

#include "elf_sign_context.h"

namespace OHOS {
namespace SignatureTools {

class ElfSignWriter {
public:
    ElfSignWriter() = default;
    ~ElfSignWriter() = default;

    void SetCtx(ElfSignContext* ctx) { this->ctx = ctx; }
    int64_t Write(const std::string& originalFile, const std::string& outputFile);

private:
    void CopyOriginal(std::ifstream& src, std::ofstream& dest, int64_t len);
    int64_t WriteNewSections(std::ofstream& dest, int64_t off);
    void WriteSectionHeaderTable(std::ofstream& dest, int64_t pos);
    void WriteElfHeader(std::ofstream& dest);
    static int64_t Align(int64_t pos, int64_t align);

    ElfSignContext* ctx = nullptr;
    int64_t newShoff = 0;
    int64_t codesignOffset = 0;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATURETOOLS_ELF_SIGN_WRITER_H
