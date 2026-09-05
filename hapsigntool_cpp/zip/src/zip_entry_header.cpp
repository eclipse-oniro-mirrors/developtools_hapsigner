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

#include "zip_entry_header.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {
ZipEntryHeader* ZipEntryHeader::GetZipEntryHeader(const std::string& bytes)
{
    ZipEntryHeader* entryHeader = new ZipEntryHeader();
    ByteBuffer bf(bytes.c_str(), bytes.size());

    int32_t entryHeaderInt32Value;
    bf.GetInt32(entryHeaderInt32Value);
    if (entryHeaderInt32Value != ZipEntryHeader::SIGNATURE) {
        delete entryHeader;
        SIGNATURE_TOOLS_LOGE("find zip entry head failed");
        return nullptr;
    }

    int16_t entryHeaderInt16Value;
    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetVersion(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetFlag(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetMethod(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetLastTime(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetLastDate(entryHeaderInt16Value);

    bf.GetInt32(entryHeaderInt32Value);
    entryHeader->SetCrc32(entryHeaderInt32Value);

    uint32_t entryHeaderUInt32Value;
    bf.GetUInt32(entryHeaderUInt32Value);
    entryHeader->SetCompressedSize(entryHeaderUInt32Value);
    entryHeader->SetCompressedSizeActual(entryHeaderUInt32Value);

    bf.GetUInt32(entryHeaderUInt32Value);
    entryHeader->SetUnCompressedSize(entryHeaderUInt32Value);
    entryHeader->SetUnCompressedSizeActual(entryHeaderUInt32Value);

    uint16_t entryHeaderUInt16Value;
    bf.GetUInt16(entryHeaderUInt16Value);
    entryHeader->SetFileNameLength(entryHeaderUInt16Value);

    bf.GetUInt16(entryHeaderUInt16Value);
    entryHeader->SetExtraLength(entryHeaderUInt16Value);

    entryHeader->SetLength(HEADER_LENGTH + entryHeader->GetFileNameLength() + entryHeader->GetExtraLength());

    return entryHeader;
}

void ZipEntryHeader::ReadFileName(const std::string& bytes)
{
    ByteBuffer bf(bytes.c_str(), bytes.size());
    if (m_fileNameLength > 0) {
        std::string nameBytes(m_fileNameLength, 0);
        bf.GetData(&nameBytes[0], m_fileNameLength);
        m_fileName = nameBytes;
    }
}

bool ZipEntryHeader::ReadExtra(const std::string& bytes)
{
    ByteBuffer bf(bytes.c_str(), bytes.size());
    if (m_extraLength > 0) {
        std::string extra(m_extraLength, 0);
        bf.GetData(&extra[0], m_extraLength);
        m_extraData = extra;

        // Parse ZIP64 Extended Information from extra field
        auto zip64Info = Zip64ExtendedInfo::Parse(extra, m_compressedSize,
            m_unCompressedSize, 0, 0);
        if (zip64Info.has_value()) {
            m_isZip64 = true;
            m_zip64ExtendedInfo = zip64Info;
            if (zip64Info->HasCompressedSize()) {
                m_compressedSizeActual = zip64Info->GetCompressedSize();
            }
            if (zip64Info->HasUnCompressedSize()) {
                m_unCompressedSizeActual = zip64Info->GetUnCompressedSize();
            }
        } else if (m_compressedSize == UINT32_MAX || m_unCompressedSize == UINT32_MAX) {
            SIGNATURE_TOOLS_LOGE("Local File Header has sentinel values but "
                                 "Zip64 Extended Info is missing in extra field");
            return false;
        }
    }
    return true;
}

std::string ZipEntryHeader::ToBytes()
{
    ByteBuffer bf(m_length);

    bf.PutInt32(SIGNATURE);
    bf.PutInt16(m_version);
    bf.PutInt16(m_flag);
    bf.PutInt16(m_method);
    bf.PutInt16(m_lastTime);
    bf.PutInt16(m_lastDate);
    bf.PutInt32(m_crc32);
    bf.PutUInt32(m_compressedSize);
    bf.PutUInt32(m_unCompressedSize);
    bf.PutUInt16(m_fileNameLength);
    bf.PutUInt16(m_extraLength);

    if (m_fileNameLength > 0) {
        bf.PutData(m_fileName.c_str(), m_fileName.size());
    }
    if (m_extraLength > 0) {
        bf.PutData(m_extraData.c_str(), m_extraData.size());
    }

    return bf.ToString();
}

bool ZipEntryHeader::UpdateForZip64Mode(bool outputIsZip64)
{
    m_isZip64 = outputIsZip64;

    if (outputIsZip64) {
        if (m_compressedSizeActual > UINT32_MAX) {
            m_compressedSize = UINT32_MAX;
        } else {
            m_compressedSize = static_cast<uint32_t>(m_compressedSizeActual);
        }
        if (m_unCompressedSizeActual > UINT32_MAX) {
            m_unCompressedSize = UINT32_MAX;
        } else {
            m_unCompressedSize = static_cast<uint32_t>(m_unCompressedSizeActual);
        }

        // version needed must be >= ZIP64_VERSION_NEEDED for ZIP64
        if (m_version < Zip64ExtendedInfo::ZIP64_VERSION_NEEDED) {
            m_version = Zip64ExtendedInfo::ZIP64_VERSION_NEEDED;
        }

        Zip64ExtendedInfo newInfo(m_compressedSizeActual, m_unCompressedSizeActual, 0, 0);
        m_zip64ExtendedInfo = newInfo;

        // Rebuild extra field
        if (!RebuildExtraField(true)) {
            return false;
        }
    } else {
        m_compressedSize = static_cast<uint32_t>(m_compressedSizeActual);
        m_unCompressedSize = static_cast<uint32_t>(m_unCompressedSizeActual);
        m_zip64ExtendedInfo = std::nullopt;

        // Rebuild extra field: strip Zip64 Extended Info
        if (!RebuildExtraField(false)) {
            return false;
        }
    }
    return true;
}

bool ZipEntryHeader::RebuildExtraField(bool includeZip64)
{
    std::string newExtra;
    if (includeZip64 && m_zip64ExtendedInfo.has_value()) {
        newExtra = m_zip64ExtendedInfo->ToBytes();
    }

    // Walk through original extra data, keep non-ZIP64 parts
    int32_t pos = 0;
    int32_t extraLen = static_cast<int32_t>(m_extraData.size());
    while (pos + Zip64ExtendedInfo::EXTRA_SUBFIELD_HEADER_SIZE <= extraLen) {
        uint16_t headerId = static_cast<uint8_t>(m_extraData[pos]) |
            (static_cast<uint16_t>(static_cast<uint8_t>(m_extraData[pos + 1])) << 8);
        uint16_t dataSize = static_cast<uint8_t>(m_extraData[pos + 2]) |
            (static_cast<uint16_t>(static_cast<uint8_t>(m_extraData[pos + 3])) << 8);
        if (headerId != Zip64ExtendedInfo::HEADER_ID) {
            newExtra.append(m_extraData, pos,
                Zip64ExtendedInfo::EXTRA_SUBFIELD_HEADER_SIZE + dataSize);
        }
        pos += Zip64ExtendedInfo::EXTRA_SUBFIELD_HEADER_SIZE + dataSize;
    }
    // Preserve trailing bytes that don't form a complete sub-field header (alignment padding)
    if (pos < extraLen) {
        newExtra.append(m_extraData, pos, extraLen - pos);
    }

    if (newExtra.size() > UINT16_MAX) {
        SIGNATURE_TOOLS_LOGE("Extra field length %zu exceeds UINT16_MAX", newExtra.size());
        return false;
    }
    m_extraData = newExtra;
    m_extraLength = static_cast<uint16_t>(newExtra.size());
    m_length = HEADER_LENGTH + m_fileNameLength + m_extraLength;
    return true;
}

int ZipEntryHeader::GetHeaderLength()
{
    return HEADER_LENGTH;
}

int ZipEntryHeader::GetSIGNATURE()
{
    return SIGNATURE;
}

short ZipEntryHeader::GetVersion()
{
    return m_version;
}

void ZipEntryHeader::SetVersion(short version)
{
    m_version = version;
}

short ZipEntryHeader::GetFlag()
{
    return m_flag;
}

void ZipEntryHeader::SetFlag(short flag)
{
    m_flag = flag;
}

short ZipEntryHeader::GetMethod()
{
    return m_method;
}

void ZipEntryHeader::SetMethod(short method)
{
    m_method = method;
}

short ZipEntryHeader::GetLastTime()
{
    return m_lastTime;
}

void ZipEntryHeader::SetLastTime(short lastTime)
{
    m_lastTime = lastTime;
}

short ZipEntryHeader::GetLastDate()
{
    return m_lastDate;
}

void ZipEntryHeader::SetLastDate(short lastDate)
{
    m_lastDate = lastDate;
}

int ZipEntryHeader::GetCrc32()
{
    return m_crc32;
}

void ZipEntryHeader::SetCrc32(int crc32)
{
    m_crc32 = crc32;
}

uint32_t ZipEntryHeader::GetCompressedSize()
{
    return m_compressedSize;
}

void ZipEntryHeader::SetCompressedSize(uint32_t compressedSize)
{
    m_compressedSize = compressedSize;
}

uint32_t ZipEntryHeader::GetUnCompressedSize()
{
    return m_unCompressedSize;
}

void ZipEntryHeader::SetUnCompressedSize(uint32_t unCompressedSize)
{
    m_unCompressedSize = unCompressedSize;
}

uint16_t ZipEntryHeader::GetFileNameLength()
{
    return m_fileNameLength;
}

void ZipEntryHeader::SetFileNameLength(uint16_t fileNameLength)
{
    m_fileNameLength = fileNameLength;
}

uint16_t ZipEntryHeader::GetExtraLength()
{
    return m_extraLength;
}

void ZipEntryHeader::SetExtraLength(uint16_t extraLength)
{
    m_extraLength = extraLength;
}

std::string ZipEntryHeader::GetFileName() const
{
    return m_fileName;
}

void ZipEntryHeader::SetFileName(const std::string& fileName)
{
    m_fileName = fileName;
}

std::string ZipEntryHeader::GetExtraData() const
{
    return m_extraData;
}

void ZipEntryHeader::SetExtraData(const std::string& extraData)
{
    m_extraData = extraData;
}

uint32_t ZipEntryHeader::GetLength()
{
    return m_length;
}

void ZipEntryHeader::SetLength(uint32_t length)
{
    m_length = length;
}

uint64_t ZipEntryHeader::GetCompressedSizeActual()
{
    return m_compressedSizeActual;
}

void ZipEntryHeader::SetCompressedSizeActual(uint64_t compressedSize)
{
    m_compressedSizeActual = compressedSize;
}

uint64_t ZipEntryHeader::GetUnCompressedSizeActual()
{
    return m_unCompressedSizeActual;
}

void ZipEntryHeader::SetUnCompressedSizeActual(uint64_t unCompressedSize)
{
    m_unCompressedSizeActual = unCompressedSize;
}

bool ZipEntryHeader::IsZip64()
{
    return m_isZip64;
}

void ZipEntryHeader::SetIsZip64(bool isZip64)
{
    m_isZip64 = isZip64;
}
} // namespace SignatureTools
} // namespace OHOS