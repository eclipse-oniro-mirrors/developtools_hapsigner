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
#include "page_info_generator.h"

#include <cstring>
#include <algorithm>

#include "file_utils.h"
#include "code_sign_block.h"
#include "page_info_extension.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

static const std::string ABC_FILE_SUFFIX = ".abc";

PageInfoGenerator::PageInfoGenerator(ZipSigner& zip, std::ifstream& input) : m_input(input)
{
    CollectRunnableFiles(zip);
}

void PageInfoGenerator::CollectRunnableFiles(ZipSigner& zip)
{
    std::vector<ZipEntry*>& entries = zip.GetZipEntries();
    for (auto& entry : entries) {
        ZipEntryData* data = entry->GetZipEntryData();
        ZipEntryHeader* header = data->GetZipEntryHeader();
        int64_t entryDataOffset = static_cast<int64_t>(entry->GetCentralDirectory()->GetOffsetActual())
            + ZipEntryHeader::HEADER_LENGTH + header->GetFileNameLength() + header->GetExtraLength();
        bool runnable = FileUtils::IsRunnableFile(header->GetFileName())
            && header->GetMethod() == ZipSigner::FILE_UNCOMPRESS_METHOD_FLAG;
        if (runnable) {
            LibExecSegment(header->GetFileName(), entryDataOffset, data->GetFileOffset(), data->GetFileSize());
            continue;
        }
        m_maxEntryDataOffset = entryDataOffset;
        break;
    }
}

void PageInfoGenerator::LibExecSegment(const std::string& fileName, int64_t entryDataOffset,
    uint64_t fileOffset, uint64_t fileSize)
{
    if (fileName.size() >= ABC_FILE_SUFFIX.size() &&
        fileName.compare(fileName.size() - ABC_FILE_SUFFIX.size(), ABC_FILE_SUFFIX.size(), ABC_FILE_SUFFIX) == 0) {
        m_excSegmentList.push_back({ ABC_M_CODE, entryDataOffset, entryDataOffset + static_cast<int64_t>(fileSize) });
        return;
    }
    std::vector<int8_t> content(fileSize);
    m_input.clear();
    m_input.seekg(static_cast<std::streampos>(fileOffset), std::ios::beg);
    m_input.read(reinterpret_cast<char*>(content.data()), fileSize);
    if (m_input.gcount() != static_cast<std::streamsize>(fileSize)) {
        SIGNATURE_TOOLS_LOGE("read runnable file content failed: %s", fileName.c_str());
        return;
    }
    ParseElfExecSegments(content, entryDataOffset);
}

bool PageInfoGenerator::ParseElfExecSegments(const std::vector<int8_t>& content, int64_t entryDataOffset)
{
    if (content.size() < MIN_ELF64_HEADER_SIZE) {
        return false;
    }
    const uint8_t* p = reinterpret_cast<const uint8_t*>(content.data());
    if (p[0] != 0x7f || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') {
        return false;
    }
    uint8_t eiClass = p[4];
    auto readU64 = [&](size_t off) -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) {
            v |= static_cast<uint64_t>(p[off + i]) << (i * 8);
        }
        return v;
    };
    auto readU16 = [&](size_t off) -> uint16_t {
        return static_cast<uint16_t>(p[off]) | (static_cast<uint16_t>(p[off + 1]) << 8);
    };
    auto readU32 = [&](size_t off) -> uint32_t {
        return static_cast<uint32_t>(p[off]) | (static_cast<uint32_t>(p[off + 1]) << 8)
            | (static_cast<uint32_t>(p[off + 2]) << 16) | (static_cast<uint32_t>(p[off + 3]) << 24);
    };
    if (eiClass != ELFCLASS64) {
        return false;
    }
    uint64_t ePhoff = readU64(ELF64_E_PHOFF_OFFSET);
    uint16_t ePhentsize = readU16(ELF64_E_PHENTSIZE_OFFSET);
    uint16_t ePhnum = readU16(ELF64_E_PHNUM_OFFSET);
    for (uint16_t i = 0; i < ePhnum; ++i) {
        size_t base = static_cast<size_t>(ePhoff) + static_cast<size_t>(i) * ePhentsize;
        if (base + ELF64_E_PHNUM_OFFSET > content.size()) {
            break;
        }
        uint32_t pFlags = readU32(base + ELF64_PH_FLAGS_OFFSET);
        if ((pFlags & PF_X_FLAG) == 0) {
            continue;
        }
        uint64_t pOffset = readU64(base + ELF64_PH_OFFSET_OFFSET);
        uint64_t pFilesz = readU64(base + ELF64_PH_FILESZ_OFFSET);
        int64_t off = entryDataOffset + static_cast<int64_t>(pOffset);
        int64_t endoff = off + static_cast<int64_t>(pFilesz);
        m_excSegmentList.push_back({ ELF_M_CODE, off, endoff });
    }
    return true;
}

std::vector<int8_t> PageInfoGenerator::GenerateBitMap()
{
    if (m_excSegmentList.empty()) {
        return std::vector<int8_t>();
    }
    int64_t len = m_maxEntryDataOffset / CodeSignBlock::PAGE_SIZE_4K * PageInfoExtension::DEFAULT_UNIT_SIZE;
    if (len <= 0) {
        return std::vector<int8_t>();
    }
    int64_t longCount = (len + (BITS_PER_LONG - 1)) / BITS_PER_LONG;
    int64_t byteLen = longCount * 8;
    std::vector<int8_t> bitmap(byteLen, 0);
    uint8_t* bytes = reinterpret_cast<uint8_t*>(bitmap.data());
    for (const auto& es : m_excSegmentList) {
        int64_t begin = (es.startOffset >> PAGE_SHIFT_4K) * PageInfoExtension::DEFAULT_UNIT_SIZE;
        int64_t endPage = (es.endOffset % CodeSignBlock::PAGE_SIZE_4K == 0)
            ? (es.endOffset >> PAGE_SHIFT_4K)
            : ((es.endOffset >> PAGE_SHIFT_4K) + 1);
        int64_t end = endPage * PageInfoExtension::DEFAULT_UNIT_SIZE;
        for (int64_t i = begin; i < end; i += PageInfoExtension::DEFAULT_UNIT_SIZE) {
            if (i < 0 || i >= len) {
                continue;
            }
            int64_t bit = (ELF_M_CODE == es.type) ? i : i + 1;
            if (bit < len) {
                bytes[bit / 8] |= (1 << (bit % 8));
            }
        }
    }
    SIGNATURE_TOOLS_LOGI("generate bitmap: maxEntryDataOffset=%lld, bitmapSize=%zu",
        static_cast<long long>(m_maxEntryDataOffset), bitmap.size());
    return bitmap;
}

} // namespace SignatureTools
} // namespace OHOS
