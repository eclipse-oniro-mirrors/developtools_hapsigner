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

#include "elf_sign_context.h"

#include <algorithm>
#include <cstring>

#include "file_utils.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

bool ElfSignContext::IsSignatureName(const std::string& name)
{
    return name == CODE_SIGN_SEC_NAME || name == PERMISSION_SEC_NAME || name == PROFILE_SEC_NAME;
}

bool ElfSignContext::IsMagicShstrtab(const SectionInfo& sec)
{
    if (sec.GetNameString() != SHSTRTAB_SEC_NAME) {
        return false;
    }
    const std::vector<uint8_t>& data = sec.GetData();
    const std::vector<uint8_t>& magic = GetShstrtabMagic();
    if (data.size() < magic.size()) {
        return false;
    }
    size_t start = data.size() - magic.size();
    for (size_t i = 0; i < magic.size(); i++) {
        if (data[start + i] != magic[i]) {
            return false;
        }
    }
    return true;
}

bool ElfSignContext::ExtractHeaderInfo(ELFIO::elfio& reader)
{
    headerInfo.fileClass = reader.get_class();
    headerInfo.encoding = reader.get_encoding();
    headerInfo.sectionEntrySize = reader.get_section_entry_size();
    ELFIO::Elf64_Off shoff = reader.get_sections_offset();
    ELFIO::Elf_Half shstrndx = reader.get_section_name_str_index();
    ELFIO::Elf_Half shnum = reader.sections.size();

    if (shoff == 0) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] No section header table (e_shoff == 0)");
        return false;
    }
    if (shstrndx == static_cast<ELFIO::Elf_Half>(ELFIO::SHN_UNDEF)) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] No section name string table (e_shstrndx == SHN_UNDEF)");
        return false;
    }
    if (shnum == 0) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] No sections found (e_shnum == 0)");
        return false;
    }
    if ((shstrndx & 0xFFFF) == static_cast<ELFIO::Elf_Half>(ELFIO::SHN_XINDEX)) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Extended section name index not supported (e_shstrndx == SHN_XINDEX)");
        return false;
    }

    headerInfo.shtOff = shoff;
    headerInfo.sectionNameStrIndex = shstrndx;
    headerInfo.shNum = shnum;
    convertor = reader.get_convertor();
    return true;
}

void ElfSignContext::ExtractSectionInfos(ELFIO::elfio& reader)
{
    origSections.clear();
    ELFIO::Elf_Half count = reader.sections.size();
    for (ELFIO::Elf_Half i = 0; i < count; i++) {
        ELFIO::section* sec = reader.sections[i];
        if (sec == nullptr) {
            continue;
        }
        SectionInfo info;
        info.SetIndex(i);
        info.SetNameOffset(sec->get_name_string_offset());
        info.SetType(sec->get_type());
        info.SetFlags(sec->get_flags());
        info.SetAddress(sec->get_address());
        info.SetOffset(sec->get_offset());
        info.SetSize(sec->get_size());
        info.SetLink(sec->get_link());
        info.SetInfo(sec->get_info());
        info.SetAddrAlign(sec->get_addr_align());
        info.SetEntSize(sec->get_entry_size());
        info.SetNameString(sec->get_name());
        info.SetNew(false);
        if (sec->get_name() == SHSTRTAB_SEC_NAME) {
            const char* rawData = sec->get_data();
            ELFIO::Elf_Xword rawSize = sec->get_size();
            if (rawData != nullptr && rawSize > 0) {
                info.SetData(rawData, static_cast<size_t>(rawSize));
            }
        }
        origSections.push_back(std::move(info));
    }
}

bool ElfSignContext::ValidateSignatureDataAtEnd()
{
    int64_t maxRetainedEnd = 0;
    int64_t minSigOffset = INT64_MAX;
    bool hasSignature = false;
    for (const SectionInfo& sec : origSections) {
        if (IsSignatureName(sec.GetNameString()) || IsMagicShstrtab(sec)) {
            hasSignature = true;
            minSigOffset = std::min(minSigOffset, static_cast<int64_t>(sec.GetOffset()));
        } else if (sec.GetType() != ELFIO::SHT_NULL && sec.GetType() != ELFIO::SHT_NOBITS
                   && sec.GetSize() > 0) {
            maxRetainedEnd = std::max(maxRetainedEnd,
                                      static_cast<int64_t>(sec.GetOffset() + sec.GetSize()));
        }
    }
    if (hasSignature && maxRetainedEnd > minSigOffset) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Signature section data is not at the end of file: "
                             "max retained end=%ld, min signature offset=%ld",
                             maxRetainedEnd, minSigOffset);
        return false;
    }
    return true;
}

bool ElfSignContext::ComputeOffset(int64_t inputFileLength)
{
    int origShnum = static_cast<int>(origSections.size());
    int64_t minOffset = inputFileLength;
    if (static_cast<int64_t>(headerInfo.shtOff + static_cast<uint64_t>(headerInfo.shNum) *
                             headerInfo.sectionEntrySize) == inputFileLength) {
        minOffset = static_cast<int64_t>(headerInfo.shtOff);
    }

    if (!ValidateSignatureDataAtEnd()) {
        return false;
    }

    for (int i = origShnum - 1; i >= 0; i--) {
        if (IsSignatureName(origSections[i].GetNameString()) ||
            IsMagicShstrtab(origSections[i])) {
            minOffset = std::min(minOffset, static_cast<int64_t>(origSections[i].GetOffset()));
            continue;
        }
        newSections.assign(origSections.begin(), origSections.begin() + i + 1);
        break;
    }

    for (const SectionInfo& newSection : newSections) {
        if (IsSignatureName(newSection.GetNameString())) {
            SIGNATURE_TOOLS_LOGE("[ElfSignContext] Can not to resign while SHT or sign section existed error");
            return false;
        }
        if (newSection.GetType() != ELFIO::SHT_NULL && newSection.GetType() != ELFIO::SHT_NOBITS
            && newSection.GetSize() > 0
            && static_cast<int64_t>(newSection.GetOffset()) > minOffset) {
            SIGNATURE_TOOLS_LOGE("[ElfSignContext] Can not to sign while sign section existed error: %s offset=%lu "
                                 "> minOffset=%ld",
                                 newSection.GetNameString().c_str(),
                                 static_cast<unsigned long>(newSection.GetOffset()), minOffset);
            return false;
        }
    }

    truncateOffset = minOffset;
    return true;
}

bool ElfSignContext::Load(ELFIO::elfio& reader, const std::string& filePath)
{
    int64_t inputFileLength = FileUtils::GetFileLen(filePath);
    if (inputFileLength < 0) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Failed to get input file length");
        return false;
    }
    if (!ExtractHeaderInfo(reader)) {
        return false;
    }
    ExtractSectionInfos(reader);
    if (!ValidateSectionNameOffsets()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Malformed section header table (out-of-range sh_name)");
        return false;
    }
    if (!ValidateSegmentBounds(reader, inputFileLength)) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Malformed program header table (segment data out of file)");
        return false;
    }
    if (!ValidateSectionDataBounds(inputFileLength)) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Malformed section header table (section data out of file)");
        return false;
    }
    return ComputeOffset(inputFileLength);
}

const SectionInfo* ElfSignContext::FindOriginalShstrtab() const
{
    for (const SectionInfo& sec : origSections) {
        if (sec.GetNameString() == SHSTRTAB_SEC_NAME && !IsMagicShstrtab(sec)) {
            return &sec;
        }
    }
    if (headerInfo.sectionNameStrIndex >= origSections.size()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Invalid section name string index");
        return nullptr;
    }
    return &origSections[headerInfo.sectionNameStrIndex];
}

bool ElfSignContext::ValidateSectionNameOffsets() const
{
    if (headerInfo.sectionNameStrIndex >= origSections.size()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Invalid section name string index");
        return false;
    }
    size_t strtabSize = origSections[headerInfo.sectionNameStrIndex].GetSize();
    for (const SectionInfo& sec : origSections) {
        if (sec.GetType() == ELFIO::SHT_NULL) {
            continue;
        }
        if (static_cast<size_t>(sec.GetNameOffset()) >= strtabSize) {
            SIGNATURE_TOOLS_LOGE("[ElfSignContext] Section %d sh_name %u out of .shstrtab range (size=%zu)",
                sec.GetIndex(), sec.GetNameOffset(), strtabSize);
            return false;
        }
    }
    return true;
}

bool ElfSignContext::ValidateSectionDataBounds(int64_t inputFileLength) const
{
    if (inputFileLength <= 0) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Invalid input file length %lld",
            static_cast<long long>(inputFileLength));
        return false;
    }
    uint64_t fileLength = static_cast<uint64_t>(inputFileLength);
    for (const SectionInfo& sec : origSections) {
        if (sec.GetType() == ELFIO::SHT_NULL || sec.GetType() == ELFIO::SHT_NOBITS || sec.GetSize() == 0) {
            continue;
        }
        uint64_t offset = static_cast<uint64_t>(sec.GetOffset());
        uint64_t size = static_cast<uint64_t>(sec.GetSize());
        if (offset > fileLength || size > fileLength - offset) {
            SIGNATURE_TOOLS_LOGE("[ElfSignContext] Section %d data offset=%llu size=%llu out of file length=%llu",
                sec.GetIndex(), static_cast<unsigned long long>(offset),
                static_cast<unsigned long long>(size), static_cast<unsigned long long>(fileLength));
            return false;
        }
    }
    return true;
}

bool ElfSignContext::ValidateSegmentBounds(ELFIO::elfio& reader, int64_t inputFileLength) const
{
    uint64_t fileLength = static_cast<uint64_t>(inputFileLength);
    uint64_t phNum = static_cast<uint64_t>(reader.segments.size());
    if (phNum == 0) {
        return true;
    }
    uint64_t phOffset = static_cast<uint64_t>(reader.get_segments_offset());
    uint64_t phTableSize = static_cast<uint64_t>(reader.get_segment_entry_size()) * phNum;
    if (phOffset > fileLength || phTableSize > fileLength - phOffset) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Program header table offset=%llu size=%llu out of file length=%llu",
            static_cast<unsigned long long>(phOffset), static_cast<unsigned long long>(phTableSize),
            static_cast<unsigned long long>(fileLength));
        return false;
    }
    for (uint64_t i = 0; i < phNum; ++i) {
        const ELFIO::segment* seg = reader.segments[static_cast<unsigned int>(i)];
        if (seg == nullptr || seg->get_type() == ELFIO::PT_NULL || seg->get_file_size() == 0) {
            continue;
        }
        uint64_t offset = static_cast<uint64_t>(seg->get_offset());
        uint64_t size = static_cast<uint64_t>(seg->get_file_size());
        if (offset > fileLength || size > fileLength - offset) {
            SIGNATURE_TOOLS_LOGE("[ElfSignContext] Segment %llu data offset=%llu size=%llu out of file length=%llu",
                static_cast<unsigned long long>(i), static_cast<unsigned long long>(offset),
                static_cast<unsigned long long>(size), static_cast<unsigned long long>(fileLength));
            return false;
        }
    }
    return true;
}

size_t ElfSignContext::ComputeShstrtabTruncateAt(size_t origDataSize) const
{
    if (origSections.size() == newSections.size()) {
        return origDataSize;
    }
    size_t maxNameEnd = 0;
    for (const SectionInfo& sec : newSections) {
        size_t nameEnd = sec.GetNameOffset() + sec.GetNameString().size() + 1;
        maxNameEnd = std::max(maxNameEnd, nameEnd);
    }
    // Clamp to the real .shstrtab buffer size to prevent out-of-bounds reads when
    // section header fields are malformed.
    return std::min(maxNameEnd, origDataSize);
}

bool ElfSignContext::BuildNewShstrtab()
{
    const SectionInfo* orgNameTabSecPtr = FindOriginalShstrtab();
    if (orgNameTabSecPtr == nullptr) {
        return false;
    }
    const SectionInfo& orgNameTabSec = *orgNameTabSecPtr;
    const std::vector<uint8_t>& origData = orgNameTabSec.GetData();
    if (origData.empty()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Failed to read .shstrtab data");
        return false;
    }

    size_t truncateAt = ComputeShstrtabTruncateAt(origData.size());
    std::vector<uint8_t> truncatedData(origData.begin(), origData.begin() + truncateAt);
    const std::string& nameStr = orgNameTabSec.GetNameString();
    const std::vector<uint8_t> nameBytes(nameStr.begin(), nameStr.end());
    size_t nameEnd = orgNameTabSec.GetNameOffset() + nameBytes.size() + 1;

    std::vector<uint8_t> newShstrtab;
    ELFIO::Elf_Word newNameOffset;
    if (nameEnd <= truncatedData.size()) {
        newShstrtab = truncatedData;
        newNameOffset = orgNameTabSec.GetNameOffset();
    } else {
        newShstrtab = truncatedData;
        newShstrtab.resize(truncatedData.size() + nameBytes.size() + 1, 0);
        newNameOffset = static_cast<ELFIO::Elf_Word>(truncatedData.size());
        std::copy(nameBytes.begin(), nameBytes.end(), newShstrtab.begin() + newNameOffset);
    }

    SectionInfo newNameTabSec = orgNameTabSec.DeepCopy();
    newNameTabSec.SetNameOffset(newNameOffset);
    newNameTabSec.SetSize(static_cast<ELFIO::Elf_Xword>(newShstrtab.size()));
    // ELF string tables must use alignment 1; never trust the inherited sh_addralign,
    // a malformed value would make the writer seek to an absurd offset (huge sparse file).
    newNameTabSec.SetAddrAlign(1);
    newNameTabSec.SetData(newShstrtab);
    newNameTabSec.SetNew(true);
    newShStrTabIndex = static_cast<ELFIO::Elf_Half>(newSections.size());
    newNameTabSec.SetIndex(static_cast<int>(newShStrTabIndex));
    newSections.push_back(std::move(newNameTabSec));

    return true;
}

bool ElfSignContext::AddSignSection(const std::string& name, int64_t addrAlign,
                                    const std::vector<uint8_t>& data)
{
    SectionInfo sec;
    sec.SetNameString(name);
    sec.SetType(ELFIO::SHT_PROGBITS);
    sec.SetAddrAlign(static_cast<ELFIO::Elf_Xword>(addrAlign));
    sec.SetData(data);
    sec.SetIndex(static_cast<int>(newSections.size()));
    sec.SetNew(true);
    if (!data.empty()) {
        sec.SetSize(static_cast<ELFIO::Elf_Xword>(data.size()));
    }

    if (newShStrTabIndex >= newSections.size()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] New .shstrtab not built yet");
        return false;
    }
    SectionInfo& shStrTabSec = newSections[newShStrTabIndex];
    std::vector<uint8_t>& shStrData = const_cast<std::vector<uint8_t>&>(shStrTabSec.GetData());
    sec.SetNameOffset(static_cast<ELFIO::Elf_Word>(shStrData.size()));

    const std::vector<uint8_t> nameBytes(name.begin(), name.end());
    shStrData.resize(shStrData.size() + nameBytes.size() + 1, 0);
    std::copy(nameBytes.begin(), nameBytes.end(), shStrData.begin() + sec.GetNameOffset());
    shStrTabSec.SetSize(static_cast<ELFIO::Elf_Xword>(shStrData.size()));

    newSections.push_back(std::move(sec));
    return true;
}

bool ElfSignContext::FinalizeShstrtab()
{
    if (newShStrTabIndex >= newSections.size()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] New .shstrtab not built yet");
        return false;
    }
    SectionInfo& shstrtab = newSections[newShStrTabIndex];
    if (!shstrtab.IsNew() || shstrtab.GetNameString() != SHSTRTAB_SEC_NAME) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] Section at newShStrTabIndex is not the new .shstrtab");
        return false;
    }
    std::vector<uint8_t>& data = const_cast<std::vector<uint8_t>&>(shstrtab.GetData());
    if (data.empty()) {
        SIGNATURE_TOOLS_LOGE("[ElfSignContext] New .shstrtab data is null");
        return false;
    }

    const std::vector<uint8_t>& magic = GetShstrtabMagic();
    size_t oldLen = data.size();
    size_t totalAdded = SHSTRNDX_SIZE + magic.size();
    data.resize(oldLen + totalAdded, 0);

    ELFIO::Elf_Half oldShstrndx = headerInfo.sectionNameStrIndex;
    data[oldLen] = static_cast<uint8_t>((oldShstrndx >> 8) & 0xFF);
    data[oldLen + 1] = static_cast<uint8_t>(oldShstrndx & 0xFF);
    std::copy(magic.begin(), magic.end(), data.begin() + oldLen + SHSTRNDX_SIZE);

    shstrtab.SetSize(static_cast<ELFIO::Elf_Xword>(data.size()));
    return true;
}

} // namespace SignatureTools
} // namespace OHOS
