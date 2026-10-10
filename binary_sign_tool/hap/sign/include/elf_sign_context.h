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

#ifndef SIGNATURETOOLS_ELF_SIGN_CONTEXT_H
#define SIGNATURETOOLS_ELF_SIGN_CONTEXT_H

#include <cstdint>
#include <string>
#include <vector>
#include <elfio.hpp>

#include "elf_header_info.h"
#include "section_info.h"
#include "constant.h"

namespace OHOS {
namespace SignatureTools {

class ElfSignContext {
public:
    static bool IsSignatureName(const std::string& name);
    static bool IsMagicShstrtab(const SectionInfo& sec);

    bool Load(ELFIO::elfio& reader, const std::string& filePath);
    bool BuildNewShstrtab();
    bool AddSignSection(const std::string& name, int64_t addrAlign, const std::vector<uint8_t>& data);
    bool FinalizeShstrtab();

    const ElfHeaderInfo& GetHeaderInfo() const { return headerInfo; }
    const std::vector<SectionInfo>& GetOrigSections() const { return origSections; }
    std::vector<SectionInfo>& GetNewSections() { return newSections; }
    int64_t GetTruncateOffset() const { return truncateOffset; }
    ELFIO::Elf_Half GetNewShStrTabIndex() const { return newShStrTabIndex; }
    const std::shared_ptr<ELFIO::endianess_convertor>& GetConvertor() const { return convertor; }

private:
    bool ExtractHeaderInfo(ELFIO::elfio& reader);
    void ExtractSectionInfos(ELFIO::elfio& reader);
    bool ComputeOffset(int64_t inputFileLength);
    bool ValidateSignatureDataAtEnd();
    bool ValidateSectionNameOffsets() const;
    bool ValidateSectionDataBounds(int64_t inputFileLength) const;
    bool ValidateSegmentBounds(ELFIO::elfio& reader, int64_t inputFileLength) const;
    const SectionInfo* FindOriginalShstrtab() const;
    size_t ComputeShstrtabTruncateAt(size_t origDataSize) const;

    ElfHeaderInfo headerInfo;
    std::vector<SectionInfo> origSections;
    std::vector<SectionInfo> newSections;
    ELFIO::Elf_Half newShStrTabIndex = 0;
    int64_t truncateOffset = 0;
    std::shared_ptr<ELFIO::endianess_convertor> convertor;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATURETOOLS_ELF_SIGN_CONTEXT_H
