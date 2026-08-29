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

#include <algorithm>
#include <cinttypes>
#include <filesystem>

#include "file_utils.h"
#include "zip_entry.h"
#include "zip_signer.h"

namespace OHOS {
namespace SignatureTools {
bool ZipSigner::Init(std::ifstream& inputFile)
{
    if (!inputFile.good()) {
        return false;
    }

    // Clean up previous state to support re-initialization
    delete m_endOfCentralDirectory;
    m_endOfCentralDirectory = nullptr;
    delete m_zip64Eocd;
    m_zip64Eocd = nullptr;
    delete m_zip64EocdLocator;
    m_zip64EocdLocator = nullptr;
    for (auto& zipEntry : m_zipEntries) {
        delete zipEntry;
    }
    m_zipEntries.clear();
    m_signingOffset = 0;
    m_cDOffset = 0;
    m_eOCDOffset = 0;
    m_signingBlock.clear();
    m_isZip64 = false;
    /* 1. get eocd data */
    m_endOfCentralDirectory = GetZipEndOfCentralDirectory(inputFile);
    if (!m_endOfCentralDirectory) {
        SIGNATURE_TOOLS_LOGE("get eocd data failed.");
        return false;
    }

    m_cDOffset = m_endOfCentralDirectory->IsZip64() ?
        m_endOfCentralDirectory->GetOffsetActual() : m_endOfCentralDirectory->GetOffset();

    /* 2. use eocd's cd offset, get cd data */
    if (!GetZipCentralDirectory(inputFile)) {
        SIGNATURE_TOOLS_LOGE("get zip central directory failed.");
        return false;
    }

    /* 3. use cd's entry offset and file size, get entry data */
    if (!GetZipEntries(inputFile)) {
        SIGNATURE_TOOLS_LOGE("get zip entries failed.");
        return false;
    }

    ZipEntry* endEntry = m_zipEntries[m_zipEntries.size() - 1];
    CentralDirectory* endCD = endEntry->GetCentralDirectory();
    ZipEntryData* endEntryData = endEntry->GetZipEntryData();
    m_signingOffset = (endCD->IsZip64() ? endCD->GetOffsetActual() : endCD->GetOffset())
        + endEntryData->GetLength();

    /* 4. file all data - eocd - cd - entry = sign block */
    m_signingBlock = GetSigningBlock(inputFile);

    return true;
}

EndOfCentralDirectory* ZipSigner::ParseZip64IfPresent(std::ifstream& input,
    EndOfCentralDirectory* eocd, uint64_t fileSize)
{
    if (!eocd->IsZip64()) {
        return eocd;
    }

    m_isZip64 = true;

    if (!ReadZip64EocdLocator(input) || !ReadZip64Eocd(input)) {
        delete eocd;
        return nullptr;
    }

    // Fill actual values from Zip64 EOCD into EOCD32
    eocd->SetThisDiskCDNumActual(m_zip64Eocd->GetThisDiskCDNum());
    eocd->SetcDTotalActual(m_zip64Eocd->GetCDTotal());
    eocd->SetcDSizeActual(m_zip64Eocd->GetCDSize());
    eocd->SetOffsetActual(m_zip64Eocd->GetOffset());

    return eocd;
}

bool ZipSigner::ReadZip64EocdLocator(std::ifstream& input)
{
    if (m_eOCDOffset < Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH) {
        SIGNATURE_TOOLS_LOGE("no room for zip64 eocd locator");
        return false;
    }
    uint64_t locatorOffset = m_eOCDOffset - Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH;
    std::string locatorStr;
    int ret = FileUtils::ReadFileByOffsetAndLength(input, locatorOffset,
        Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH, locatorStr);
    if (ret != RET_OK) {
        SIGNATURE_TOOLS_LOGE("read zip64 eocd locator failed");
        return false;
    }
    auto locator = Zip64EndOfCentralDirectoryLocator::GetByBytes(locatorStr);
    if (!locator) {
        SIGNATURE_TOOLS_LOGE("parse zip64 eocd locator failed");
        return false;
    }
    m_zip64EocdLocator = new Zip64EndOfCentralDirectoryLocator(locator.value());
    return true;
}

bool ZipSigner::ReadZip64Eocd(std::ifstream& input)
{
    uint64_t zip64EocdOffset = m_zip64EocdLocator->GetZip64EocdOffset();
    std::string zip64EocdStr;
    int ret = FileUtils::ReadFileByOffsetAndLength(input, zip64EocdOffset,
        Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH, zip64EocdStr);
    if (ret != RET_OK) {
        SIGNATURE_TOOLS_LOGE("read zip64 eocd failed");
        return false;
    }
    auto zip64Eocd = Zip64EndOfCentralDirectory::GetByBytes(zip64EocdStr);
    if (!zip64Eocd) {
        SIGNATURE_TOOLS_LOGE("parse zip64 eocd failed");
        return false;
    }
    m_zip64Eocd = new Zip64EndOfCentralDirectory(zip64Eocd.value());
    return true;
}

EndOfCentralDirectory* ZipSigner::GetZipEndOfCentralDirectory(std::ifstream& input)
{
    /* move file pointer to the end */
    input.seekg(0, std::ios::end);
    uint64_t fileSize = static_cast<uint64_t>(input.tellg());
    /* move file pointer to the begin */
    input.seekg(0, std::ios::beg);

    if (fileSize < EndOfCentralDirectory::EOCD_LENGTH) {
        SIGNATURE_TOOLS_LOGE("find zip eocd failed");
        return nullptr;
    }

    /* try to read EOCD without comment */
    int eocdLength = EndOfCentralDirectory::EOCD_LENGTH;
    m_eOCDOffset = fileSize - eocdLength;

    std::string retStr;
    int ret = FileUtils::ReadFileByOffsetAndLength(input, m_eOCDOffset, eocdLength, retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE("read eocd without comment failed in file");
        return nullptr;
    }

    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(retStr);
    if (eocdByBytes) {
        return ParseZip64IfPresent(input, eocdByBytes.value(), fileSize);
    }

    /* try to search EOCD with comment */
    uint64_t eocdMaxLength = std::min(static_cast<uint64_t>(EndOfCentralDirectory::EOCD_LENGTH + MAX_COMMENT_LENGTH),
        fileSize);
    m_eOCDOffset = static_cast<uint64_t>(input.tellg()) - eocdMaxLength;

    retStr.clear();
    ret = FileUtils::ReadFileByOffsetAndLength(input, m_eOCDOffset, eocdMaxLength, retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE("read eocd with comment failed in file");
        return nullptr;
    }

    for (uint64_t start = 0; start < eocdMaxLength; start++) {
        eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(retStr, start);
        if (eocdByBytes) {
            m_eOCDOffset += start;
            return ParseZip64IfPresent(input, eocdByBytes.value(), fileSize);
        }
    }
    SIGNATURE_TOOLS_LOGE("read zip failed: can not find eocd in file");
    PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "can not find eocd in file");
    return nullptr;
}

bool ZipSigner::GetZipCentralDirectory(std::ifstream& input)
{
    input.seekg(0, std::ios::beg);

    uint64_t cDtotalActual = m_endOfCentralDirectory->IsZip64() ?
        m_endOfCentralDirectory->GetcDTotalActual() : m_endOfCentralDirectory->GetcDTotal();
    m_zipEntries.reserve(static_cast<size_t>(cDtotalActual));
    /* read full central directory bytes */
    std::string retStr;

    uint64_t cDSizeActual = m_endOfCentralDirectory->IsZip64() ?
        m_endOfCentralDirectory->GetcDSizeActual() : m_endOfCentralDirectory->GetcDSize();
    int ret = FileUtils::ReadFileByOffsetAndLength(input, m_cDOffset, cDSizeActual, retStr);
    if (ret != RET_OK) {
        SIGNATURE_TOOLS_LOGE("read full central directory failed in file");
        return false;
    }

    if (retStr.size() < CentralDirectory::CD_LENGTH) {
        SIGNATURE_TOOLS_LOGE("find zip cd failed");
        return false;
    }

    ByteBuffer bf(retStr.c_str(), retStr.size());

    std::string::size_type offset = 0;
    /* one by one format central directory */
    while (offset < retStr.size()) {
        CentralDirectory* cd = new CentralDirectory();
        if (!CentralDirectory::GetCentralDirectory(bf, cd)) {
            return false;
        }
        ZipEntry* entry = new ZipEntry();
        entry->SetCentralDirectory(cd);
        m_zipEntries.emplace_back(entry);
        offset += cd->GetLength();
    }

    uint64_t cdEndOffset = offset + m_cDOffset;
    if (m_isZip64) {
        // ZIP64: CD end → Zip64 EOCD → Zip64 EOCD Locator → EOCD32
        uint64_t expectedEocdOffset = cdEndOffset +
            Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH +
            Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH;
        if (expectedEocdOffset != m_eOCDOffset) {
            SIGNATURE_TOOLS_LOGE("cd end offset plus zip64 structures not equals to eocd offset"
                ", cdEnd: %" PRIu64 ", expectedEocd: %" PRIu64 ", actualEocd: %" PRIu64,
                cdEndOffset, expectedEocdOffset, m_eOCDOffset);
            return false;
        }
    } else {
        if (cdEndOffset != m_eOCDOffset) {
            SIGNATURE_TOOLS_LOGE("cd end offset not equals to eocd offset");
            return false;
        }
    }
    return true;
}

std::string ZipSigner::GetSigningBlock(std::ifstream& file)
{
    int64_t size = static_cast<int64_t>(m_cDOffset) - static_cast<int64_t>(m_signingOffset);
    if (size < 0) {
        SIGNATURE_TOOLS_LOGE("signing offset in front of entry end");
        return "";
    }
    if (size == 0) {
        return "";
    }

    std::string retStr;
    int ret = FileUtils::ReadFileByOffsetAndLength(file, m_signingOffset, size, retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE("read signing block failed in file");
        return "";
    }
    return retStr;
}

bool ZipSigner::GetZipEntries(std::ifstream& input)
{
    /* use central directory data, find entry data */
    for (auto& entry : m_zipEntries) {
        CentralDirectory* cd = entry->GetCentralDirectory();
        uint64_t offset = cd->IsZip64() ? cd->GetOffsetActual() : cd->GetOffset();
        uint64_t unCompressedSize = cd->IsZip64() ? cd->GetUnCompressedSizeActual() : cd->GetUnCompressedSize();
        uint64_t compressedSize = cd->IsZip64() ? cd->GetCompressedSizeActual() : cd->GetCompressedSize();
        uint64_t fileSize = cd->GetMethod() == FILE_UNCOMPRESS_METHOD_FLAG ? unCompressedSize : compressedSize;

        ZipEntryData* zipEntryData = ZipEntryData::GetZipEntry(input, offset, fileSize);
        if (!zipEntryData) {
            return false;
        }
        if (m_cDOffset - offset < zipEntryData->GetLength()) {
            SIGNATURE_TOOLS_LOGE("cd offset in front of entry end");
            return false;
        }
        entry->SetZipEntryData(zipEntryData);

        ZipEntryHeader* header = zipEntryData->GetZipEntryHeader();
        header->SetCompressedSizeActual(compressedSize);
        header->SetUnCompressedSizeActual(unCompressedSize);
        if (header->GetCompressedSize() == UINT32_MAX && compressedSize <= UINT32_MAX) {
            header->SetCompressedSize(static_cast<uint32_t>(compressedSize));
        }
        if (header->GetUnCompressedSize() == UINT32_MAX && unCompressedSize <= UINT32_MAX) {
            header->SetUnCompressedSize(static_cast<uint32_t>(unCompressedSize));
        }
    }
    return true;
}

bool ZipSigner::WriteZipEntries(std::ifstream& input, std::ofstream& output)
{
    for (const auto& entry : m_zipEntries) {
        ZipEntryData* zipEntryData = entry->GetZipEntryData();
        ZipEntryHeader* header = zipEntryData->GetZipEntryHeader();
        std::string zipEntryHeaderStr = header->ToBytes();
        if (!FileUtils::WriteByteToOutFile(zipEntryHeaderStr, output)) {
            return false;
        }

        uint64_t fileOffset = zipEntryData->GetFileOffset();
        uint64_t fileSize = zipEntryData->GetFileSize();
        bool isSuccess = FileUtils::AppendWriteFileByOffsetToFile(input, output, fileOffset, fileSize);
        if (!isSuccess) {
            SIGNATURE_TOOLS_LOGE("write zip data failed");
            return false;
        }
        DataDescriptor* dataDescriptor = zipEntryData->GetDataDescriptor();
        if (dataDescriptor) {
            std::string dataDescriptorStr = dataDescriptor->ToBytes();
            if (!FileUtils::WriteByteToOutFile(dataDescriptorStr, output)) {
                return false;
            }
        }
    }
    return true;
}

bool ZipSigner::WriteTrailingSections(std::ofstream& output)
{
    if (!m_signingBlock.empty()) {
        if (!FileUtils::WriteByteToOutFile(m_signingBlock, output)) {
            return false;
        }
    }

    for (const auto& entry : m_zipEntries) {
        CentralDirectory* cd = entry->GetCentralDirectory();
        if (!FileUtils::WriteByteToOutFile(cd->ToBytes(), output)) {
            return false;
        }
    }

    if (m_isZip64 && m_zip64Eocd) {
        if (!FileUtils::WriteByteToOutFile(m_zip64Eocd->ToBytes(), output)) {
            return false;
        }
    }
    if (m_isZip64 && m_zip64EocdLocator) {
        if (!FileUtils::WriteByteToOutFile(m_zip64EocdLocator->ToBytes(), output)) {
            return false;
        }
    }

    if (!FileUtils::WriteByteToOutFile(m_endOfCentralDirectory->ToBytes(), output)) {
        return false;
    }
    return true;
}

bool ZipSigner::ToFile(std::ifstream& input, std::ofstream& output)
{
    SIGNATURE_TOOLS_LOGI("Zip To File begin");
    if (!input.good()) {
        SIGNATURE_TOOLS_LOGE("read zip input file failed");
        return false;
    }
    if (!output.good()) {
        SIGNATURE_TOOLS_LOGE("read zip output file failed");
        return false;
    }

    if (!WriteZipEntries(input, output)) {
        return false;
    }
    if (!WriteTrailingSections(output)) {
        return false;
    }

    SIGNATURE_TOOLS_LOGI("Zip To File end");
    return true;
}

void ZipSigner::Alignment(int alignment)
{
    Sort();
    bool isFirstUnRunnableFile = true;
    for (const auto& entry : m_zipEntries) {
        ZipEntryData* zipEntryData = entry->GetZipEntryData();
        short method = zipEntryData->GetZipEntryHeader()->GetMethod();
        if (method != FILE_UNCOMPRESS_METHOD_FLAG && !isFirstUnRunnableFile) {
            /* only align uncompressed entry and the first unrunnable entry. */
            break;
        }
        int alignBytes;
        if (method == FILE_UNCOMPRESS_METHOD_FLAG &&
            FileUtils::IsRunnableFile(zipEntryData->GetZipEntryHeader()->GetFileName())) {
            /* .abc and .so file align 4096 byte. */
            alignBytes = 4096;
        } else if (isFirstUnRunnableFile) {
            /* the first file after runnable file, align 4096 byte. */
            alignBytes = 4096;
            isFirstUnRunnableFile = false;
        } else if (zipEntryData->GetZipEntryHeader()->GetFileName().find("resources/resfile/") == 0 &&
                   zipEntryData->GetFileSize() >= ONE_MB) {
            /* resources/resfile/ directory file >= 1MB, align 4096 byte. */
            alignBytes = 4096;
        } else {
            /* normal file align 4 byte. */
            alignBytes = alignment;
        }
        int add = entry->Alignment(alignBytes);
        if (add > 0) {
            ResetOffset();
        }
    }
}

void ZipSigner::RemoveSignBlock()
{
    m_signingBlock = std::string();
    ResetOffset();
}

void ZipSigner::Sort()
{
    /* sort uncompress file (so, abc, an) - other uncompress file - compress file */
    std::sort(m_zipEntries.begin(), m_zipEntries.end(), [&](ZipEntry* entry1, ZipEntry* entry2) {
        short entry1Method = entry1->GetZipEntryData()->GetZipEntryHeader()->GetMethod();
        short entry2Method = entry2->GetZipEntryData()->GetZipEntryHeader()->GetMethod();
        std::string entry1FileName = entry1->GetZipEntryData()->GetZipEntryHeader()->GetFileName();
        std::string entry2FileName = entry2->GetZipEntryData()->GetZipEntryHeader()->GetFileName();
        if (entry1Method == FILE_UNCOMPRESS_METHOD_FLAG && entry2Method == FILE_UNCOMPRESS_METHOD_FLAG) {
            bool isRunnableFile1 = FileUtils::IsRunnableFile(entry1FileName);
            bool isRunnableFile2 = FileUtils::IsRunnableFile(entry2FileName);
            if (isRunnableFile1 && isRunnableFile2) {
                return entry1FileName < entry2FileName;
            } else if (isRunnableFile1) {
                return true;
            } else if (isRunnableFile2) {
                return false;
            }
        } else if (entry1Method == FILE_UNCOMPRESS_METHOD_FLAG) {
            return true;
        } else if (entry2Method == FILE_UNCOMPRESS_METHOD_FLAG) {
            return false;
        }
        return entry1FileName < entry2FileName;
    });
    ResetOffset();
}

void ZipSigner::UpdateEntriesForMode(bool zip64)
{
    for (const auto& entry : m_zipEntries) {
        entry->GetCentralDirectory()->UpdateForZip64Mode(zip64);
        entry->GetZipEntryData()->GetZipEntryHeader()->UpdateForZip64Mode(zip64);
        if (auto* desc = entry->GetZipEntryData()->GetDataDescriptor()) {
            // DataDescriptor ZIP64 mode is per-entry: only use 8-byte fields when
            // the entry's compressed/uncompressed size overflows UINT32_MAX.
            bool overflow = zip64 &&
                (entry->GetZipEntryData()->GetZipEntryHeader()->GetCompressedSizeActual() > UINT32_MAX ||
                 entry->GetZipEntryData()->GetZipEntryHeader()->GetUnCompressedSizeActual() > UINT32_MAX);
            desc->SetIsZip64(overflow);
        }
    }
}

uint64_t ZipSigner::RecalcLengthsAndOffsets(bool useZip64Offset)
{
    for (const auto& entry : m_zipEntries) {
        auto* data = entry->GetZipEntryData();
        auto* desc = data->GetDataDescriptor();
        int desLen = desc ? (desc->IsZip64() ? DataDescriptor::DES_LENGTH_ZIP64 : DataDescriptor::DES_LENGTH) : 0;
        data->SetLength(data->GetZipEntryHeader()->GetLength() + data->GetFileSize() + desLen);
    }
    uint64_t offset = 0;
    for (const auto& entry : m_zipEntries) {
        auto* cd = entry->GetCentralDirectory();
        cd->SetOffsetActual(offset);
        if (useZip64Offset) {
            cd->UpdateZip64OffsetAndRebuild(offset);
        } else {
            cd->SetOffset(offset > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(offset));
        }
        offset += entry->GetZipEntryData()->GetLength();
    }
    return offset + (m_signingBlock.empty() ? 0 : m_signingBlock.size());
}

void ZipSigner::FillEocdAndZip64(bool needZip64)
{
    uint64_t cdLength = 0;
    for (const auto& entry : m_zipEntries) {
        cdLength += entry->GetCentralDirectory()->GetLength();
    }
    m_endOfCentralDirectory->SetOffset(static_cast<uint32_t>(m_cDOffset));
    m_endOfCentralDirectory->SetOffsetActual(m_cDOffset);
    m_endOfCentralDirectory->SetcDSize(static_cast<uint32_t>(cdLength));
    m_endOfCentralDirectory->SetcDSizeActual(cdLength);
    m_endOfCentralDirectory->SetThisDiskCDNum(static_cast<uint16_t>(m_zipEntries.size()));
    m_endOfCentralDirectory->SetThisDiskCDNumActual(m_zipEntries.size());
    m_endOfCentralDirectory->SetcDTotal(static_cast<uint16_t>(m_zipEntries.size()));
    m_endOfCentralDirectory->SetcDTotalActual(m_zipEntries.size());
    m_eOCDOffset = m_cDOffset + cdLength;

    if (needZip64) {
        m_eOCDOffset += Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH +
            Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH;
        m_isZip64 = true;
        m_endOfCentralDirectory->SetIsZip64(true);
        m_endOfCentralDirectory->SetcDTotal(UINT16_MAX);
        m_endOfCentralDirectory->SetThisDiskCDNum(UINT16_MAX);
        m_endOfCentralDirectory->SetcDSize(UINT32_MAX);
        m_endOfCentralDirectory->SetOffset(UINT32_MAX);
        if (!m_zip64Eocd) {
            m_zip64Eocd = new Zip64EndOfCentralDirectory();
            m_zip64Eocd->SetSizeOfZip64Eocd(
                Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH - Zip64EndOfCentralDirectory::ZIP64_EOCD_FIXED_PART_SIZE);
        }
        m_zip64Eocd->SetThisDiskCDNum(m_zipEntries.size());
        m_zip64Eocd->SetCDTotal(m_zipEntries.size());
        m_zip64Eocd->SetCDSize(cdLength);
        m_zip64Eocd->SetOffset(m_cDOffset);
        if (!m_zip64EocdLocator) {
            m_zip64EocdLocator = new Zip64EndOfCentralDirectoryLocator();
        }
        m_zip64EocdLocator->SetZip64EocdOffset(m_cDOffset + cdLength);
    } else {
        m_isZip64 = false;
        m_endOfCentralDirectory->SetIsZip64(false);
    }
}

void ZipSigner::ResetOffset()
{
    // Step 1: Determine whether ZIP64 output is needed
    bool needZip64 = m_forceZip64 || m_isZip64 || m_zipEntries.size() > UINT16_MAX;
    if (!needZip64) {
        for (const auto& entry : m_zipEntries) {
            if (entry->GetCentralDirectory()->GetCompressedSizeActual() > UINT32_MAX ||
                entry->GetCentralDirectory()->GetUnCompressedSizeActual() > UINT32_MAX ||
                entry->GetCentralDirectory()->GetDiskNumStartActual() > UINT16_MAX) {
                needZip64 = true;
                break;
            }
        }
    }
    // Step 2-4: Update mode → recalc → check overflow → redo if needed
    UpdateEntriesForMode(needZip64);
    m_cDOffset = RecalcLengthsAndOffsets(false);
    if (!needZip64 && m_cDOffset > UINT32_MAX) {
        needZip64 = true;
        UpdateEntriesForMode(true);
        m_cDOffset = RecalcLengthsAndOffsets(false);
    }
    // Step 4.5: Update Zip64 offset in CD extra field; redo if CD length changed
    if (needZip64) {
        bool lengthChanged = false;
        for (const auto& entry : m_zipEntries) {
            auto* cd = entry->GetCentralDirectory();
            uint32_t oldLength = cd->GetLength();
            cd->UpdateZip64OffsetAndRebuild(cd->GetOffsetActual());
            if (cd->GetLength() != oldLength) {
                lengthChanged = true;
            }
        }
        if (lengthChanged) {
            m_cDOffset = RecalcLengthsAndOffsets(true);
        }
    }
    // Step 5: Fill EOCD and Zip64 structures
    FillEocdAndZip64(needZip64);
}

std::vector<ZipEntry*>& ZipSigner::GetZipEntries()
{
    return m_zipEntries;
}

void ZipSigner::SetZipEntries(const std::vector<ZipEntry*>& zipEntries)
{
    m_zipEntries = zipEntries;
}

uint64_t ZipSigner::GetSigningOffset()
{
    return m_signingOffset;
}

void ZipSigner::SetSigningOffset(uint64_t signingOffset)
{
    m_signingOffset = signingOffset;
}

std::string ZipSigner::GetSigningBlock()
{
    return m_signingBlock;
}

void ZipSigner::SetSigningBlock(const std::string& signingBlock)
{
    m_signingBlock = signingBlock;
}

uint64_t ZipSigner::GetCDOffset()
{
    return m_cDOffset;
}

void ZipSigner::SetCDOffset(uint64_t cDOffset)
{
    m_cDOffset = cDOffset;
}

uint64_t ZipSigner::GetEOCDOffset()
{
    return m_eOCDOffset;
}

void ZipSigner::SetEOCDOffset(uint64_t eOCDOffset)
{
    m_eOCDOffset = eOCDOffset;
}

EndOfCentralDirectory* ZipSigner::GetEndOfCentralDirectory()
{
    return m_endOfCentralDirectory;
}

void ZipSigner::SetEndOfCentralDirectory(EndOfCentralDirectory* endOfCentralDirectory)
{
    m_endOfCentralDirectory = endOfCentralDirectory;
}

void ZipSigner::SetForceZip64(bool forceZip64)
{
    m_forceZip64 = forceZip64;
}
} // namespace SignatureTools
} // namespace OHOS