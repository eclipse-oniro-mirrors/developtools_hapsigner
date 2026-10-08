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

#include "elf_sign_writer.h"

#include <algorithm>
#include <cstring>
#include <fstream>

#include "signature_tools_log.h"
#include "constant.h"

namespace OHOS {
namespace SignatureTools {

static constexpr int BUFFER_SIZE = 1024 * 1024;
static constexpr int64_t SECTION_HEADER_TABLE_ALIGN_32 = 4; // sizeof(Elf32_Addr)
static constexpr int64_t SECTION_HEADER_TABLE_ALIGN_64 = 8; // sizeof(Elf64_Addr)

int64_t ElfSignWriter::Write(const std::string& originalFile, const std::string& outputFile)
{
    int64_t truncateOffset = ctx->GetTruncateOffset();
    std::ifstream src(originalFile, std::ios::binary);
    if (!src) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to open source file: %s", originalFile.c_str());
        return -1;
    }
    std::ofstream dest(outputFile, std::ios::binary | std::ios::trunc);
    if (!dest) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to open destination file: %s", outputFile.c_str());
        return -1;
    }

    CopyOriginal(src, dest, truncateOffset);
    if (writeFailed) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Aborted: copy original data failed");
        return -1;
    }
    int64_t pos = WriteNewSections(dest, truncateOffset);
    if (writeFailed) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Aborted: write new sections failed");
        return -1;
    }
    WriteSectionHeaderTable(dest, pos);
    if (writeFailed) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Aborted: write section header table failed");
        return -1;
    }
    WriteElfHeader(dest);
    if (writeFailed) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Aborted: patch ELF header failed");
        return -1;
    }
    dest.flush();
    if (!dest) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to flush output file: %s", outputFile.c_str());
        return -1;
    }
    return codesignOffset;
}

void ElfSignWriter::CopyOriginal(std::ifstream& src, std::ofstream& dest, int64_t len)
{
    int64_t transferred = 0;
    std::vector<char> buffer(BUFFER_SIZE);
    while (transferred < len && !writeFailed) {
        int64_t count = std::min(len - transferred, static_cast<int64_t>(BUFFER_SIZE));
        src.read(buffer.data(), count);
        int64_t n = src.gcount();
        if (n <= 0) {
            SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to read source at position %ld", transferred);
            writeFailed = true;
            return;
        }
        dest.write(buffer.data(), n);
        if (!dest) {
            SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to write output at position %ld", transferred);
            writeFailed = true;
            return;
        }
        transferred += n;
    }
}

int64_t ElfSignWriter::WriteNewSections(std::ofstream& dest, int64_t off)
{
    int64_t pos = off;
    std::vector<SectionInfo>& sections = ctx->GetNewSections();
    for (SectionInfo& sec : sections) {
        if (writeFailed) {
            break;
        }
        if (!sec.IsNew()) {
            continue;
        }
        pos = Align(pos, static_cast<int64_t>(sec.GetAddrAlign()));
        sec.SetOffset(static_cast<ELFIO::Elf64_Off>(pos));
        if (sec.GetNameString() == CODE_SIGN_SEC_NAME) {
            codesignOffset = pos;
        }
        const std::vector<uint8_t>& data = sec.GetData();
        if (!data.empty()) {
            dest.seekp(pos, std::ios::beg);
            dest.write(reinterpret_cast<const char*>(data.data()), data.size());
        } else if (sec.GetSize() > 0) {
            std::vector<char> zeros(static_cast<size_t>(sec.GetSize()), 0);
            dest.seekp(pos, std::ios::beg);
            dest.write(zeros.data(), zeros.size());
        }
        if (!dest) {
            SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to write section %s at offset %ld",
                                 sec.GetNameString().c_str(), pos);
            writeFailed = true;
            break;
        }
        pos += static_cast<int64_t>(sec.GetSize());
    }
    return pos;
}

void ElfSignWriter::WriteSectionHeaderTable(std::ofstream& dest, int64_t pos)
{
    bool is64 = ctx->GetHeaderInfo().fileClass == ELFIO::ELFCLASS64;
    int64_t shoffAlign = is64 ? SECTION_HEADER_TABLE_ALIGN_64 : SECTION_HEADER_TABLE_ALIGN_32;
    newShoff = Align(pos, shoffAlign);
    int entrySize = ctx->GetHeaderInfo().sectionEntrySize;
    const auto& convertor = ctx->GetConvertor();
    std::vector<SectionInfo>& sections = ctx->GetNewSections();

    for (size_t i = 0; i < sections.size(); i++) {
        if (writeFailed) {
            break;
        }
        int64_t entryPos = newShoff + static_cast<int64_t>(i) * entrySize;
        std::string buf = sections[i].ToBuffer(is64, convertor, entrySize);
        dest.seekp(entryPos, std::ios::beg);
        dest.write(buf.data(), buf.size());
        if (!dest) {
            SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to write SHT entry %zu at offset %ld", i, entryPos);
            writeFailed = true;
            break;
        }
    }
}

void ElfSignWriter::WriteElfHeader(std::ofstream& dest)
{
    bool is64 = ctx->GetHeaderInfo().fileClass == ELFIO::ELFCLASS64;
    const auto& convertor = ctx->GetConvertor();

    int shoffPos = is64 ? 0x28 : 0x20;
    dest.seekp(shoffPos, std::ios::beg);
    if (is64) {
        uint64_t shoffVal = (*convertor)(static_cast<uint64_t>(newShoff));
        dest.write(reinterpret_cast<const char*>(&shoffVal), sizeof(uint64_t));
    } else {
        uint32_t shoff32 = (*convertor)(static_cast<uint32_t>(newShoff));
        dest.write(reinterpret_cast<const char*>(&shoff32), sizeof(uint32_t));
    }
    if (!dest) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to patch e_shoff at %d", shoffPos);
        writeFailed = true;
        return;
    }

    int shnumPos = is64 ? 0x3C : 0x30;
    uint16_t newShnum = static_cast<uint16_t>(ctx->GetNewSections().size());
    newShnum = (*convertor)(newShnum);
    dest.seekp(shnumPos, std::ios::beg);
    dest.write(reinterpret_cast<const char*>(&newShnum), sizeof(uint16_t));
    if (!dest) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to patch e_shnum at %d", shnumPos);
        writeFailed = true;
        return;
    }

    int shstrndxPos = is64 ? 0x3E : 0x32;
    uint16_t newShstrndx = ctx->GetNewShStrTabIndex();
    newShstrndx = (*convertor)(newShstrndx);
    dest.seekp(shstrndxPos, std::ios::beg);
    dest.write(reinterpret_cast<const char*>(&newShstrndx), sizeof(uint16_t));
    if (!dest) {
        SIGNATURE_TOOLS_LOGE("[ElfSignWriter] Failed to patch e_shstrndx at %d", shstrndxPos);
        writeFailed = true;
        return;
    }
}

int64_t ElfSignWriter::Align(int64_t pos, int64_t align)
{
    if (align <= 0) {
        return pos;
    }
    int64_t remainder = pos % align;
    if (remainder == 0) {
        return pos;
    }
    return pos + (align - remainder);
}

} // namespace SignatureTools
} // namespace OHOS
