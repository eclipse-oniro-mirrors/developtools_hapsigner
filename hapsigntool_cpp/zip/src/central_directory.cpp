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

#include "central_directory.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {
bool CentralDirectory::GetCentralDirectory(ByteBuffer& bf, CentralDirectory* cd)
{
    int signatureValue;
    bf.GetInt32(signatureValue);
    if (signatureValue != SIGNATURE) {
        SIGNATURE_TOOLS_LOGE("find zip central directory failed");
        return false;
    }

    SetCentralDirectoryValues(bf, cd);

    uint16_t fileNameLength = cd->GetFileNameLength();
    if (fileNameLength > 0) {
        std::string readFileName(fileNameLength, 0);
        bf.GetData(&readFileName[0], fileNameLength);
        cd->SetFileName(readFileName);
    }
    uint16_t extraLength = cd->GetExtraLength();
    if (extraLength > 0) {
        std::string extra(extraLength, 0);
        bf.GetData(&extra[0], extraLength);
        cd->SetExtraData(extra);

        if (!ParseZip64ExtendedInfo(extra, cd)) {
            return false;
        }
    }
    uint16_t commentLength = cd->GetCommentLength();
    if (commentLength > 0) {
        std::string readComment(commentLength, 0);
        bf.GetData(&readComment[0], commentLength);
        cd->SetComment(readComment);
    }
    cd->SetLength(CD_LENGTH + fileNameLength + extraLength + commentLength);

    return true;
}

bool CentralDirectory::ParseZip64ExtendedInfo(const std::string& extra, CentralDirectory* cd)
{
    auto zip64Info = Zip64ExtendedInfo::Parse(extra, cd->GetCompressedSize(),
        cd->GetUnCompressedSize(), cd->GetOffset(), cd->GetDiskNumStart());
    if (zip64Info.has_value()) {
        cd->SetIsZip64(true);
        cd->SetZip64ExtendedInfo(zip64Info);
        if (zip64Info->HasCompressedSize()) {
            cd->SetCompressedSizeActual(zip64Info->GetCompressedSize());
        }
        if (zip64Info->HasUnCompressedSize()) {
            cd->SetUnCompressedSizeActual(zip64Info->GetUnCompressedSize());
        }
        if (zip64Info->HasLocalHeaderOffset()) {
            cd->SetOffsetActual(zip64Info->GetLocalHeaderOffset());
        }
        if (zip64Info->HasDiskNumStart()) {
            cd->SetDiskNumStartActual(zip64Info->GetDiskNumStart());
        }
    } else if (cd->GetCompressedSize() == UINT32_MAX ||
               cd->GetUnCompressedSize() == UINT32_MAX ||
               cd->GetOffset() == UINT32_MAX ||
               cd->GetDiskNumStart() == UINT16_MAX) {
        SIGNATURE_TOOLS_LOGE("Central Directory has sentinel values but "
                             "Zip64 Extended Info is missing in extra field");
        return false;
    }
    return true;
}

void CentralDirectory::SetCentralDirectoryValues(ByteBuffer& bf, CentralDirectory* cd)
{
    int16_t centralDirectoryInt16Value;
    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetVersion(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetVersionExtra(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetFlag(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetMethod(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetLastTime(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetLastDate(centralDirectoryInt16Value);

    int32_t centralDirectoryInt32Value;
    bf.GetInt32(centralDirectoryInt32Value);
    cd->SetCrc32(centralDirectoryInt32Value);

    uint32_t centralDirectoryUInt32Value;
    bf.GetUInt32(centralDirectoryUInt32Value);
    cd->SetCompressedSize(centralDirectoryUInt32Value);
    cd->SetCompressedSizeActual(centralDirectoryUInt32Value);

    bf.GetUInt32(centralDirectoryUInt32Value);
    cd->SetUnCompressedSize(centralDirectoryUInt32Value);
    cd->SetUnCompressedSizeActual(centralDirectoryUInt32Value);

    uint16_t centralDirectoryUInt16Value;
    bf.GetUInt16(centralDirectoryUInt16Value);
    cd->SetFileNameLength(centralDirectoryUInt16Value);

    bf.GetUInt16(centralDirectoryUInt16Value);
    cd->SetExtraLength(centralDirectoryUInt16Value);

    bf.GetUInt16(centralDirectoryUInt16Value);
    cd->SetCommentLength(centralDirectoryUInt16Value);

    bf.GetUInt16(centralDirectoryUInt16Value);
    cd->SetDiskNumStart(centralDirectoryUInt16Value);
    cd->SetDiskNumStartActual(centralDirectoryUInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetInternalFile(centralDirectoryInt16Value);

    bf.GetInt32(centralDirectoryInt32Value);
    cd->SetExternalFile(centralDirectoryInt32Value);

    bf.GetUInt32(centralDirectoryUInt32Value);
    cd->SetOffset(centralDirectoryUInt32Value);
    cd->SetOffsetActual(centralDirectoryUInt32Value);
}

std::string CentralDirectory::ToBytes()
{
    ByteBuffer bf(m_length);
    bf.PutInt32(SIGNATURE);
    bf.PutInt16(m_version);
    bf.PutInt16(m_versionExtra);
    bf.PutInt16(m_flag);
    bf.PutInt16(m_method);
    bf.PutInt16(m_lastTime);
    bf.PutInt16(m_lastDate);
    bf.PutInt32(m_crc32);
    bf.PutUInt32(m_compressedSize);
    bf.PutUInt32(m_unCompressedSize);
    bf.PutUInt16(m_fileNameLength);
    bf.PutUInt16(m_extraLength);
    bf.PutUInt16(m_commentLength);
    bf.PutUInt16(m_diskNumStart);
    bf.PutInt16(m_internalFile);
    bf.PutInt32(m_externalFile);
    bf.PutUInt32(m_offset);

    if (m_fileNameLength > 0) {
        bf.PutData(m_fileName.c_str(), m_fileName.size());
    }
    if (m_extraLength > 0) {
        bf.PutData(m_extraData.c_str(), m_extraData.size());
    }
    if (m_commentLength > 0) {
        bf.PutData(m_comment.c_str(), m_comment.size());
    }

    return bf.ToString();
}

bool CentralDirectory::UpdateForZip64Mode(bool outputIsZip64)
{
    m_isZip64 = outputIsZip64;

    if (outputIsZip64) {
        // ZIP64 output: set sentinel values for overflow fields, update Zip64 Extended Info
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
        if (m_offsetActual > UINT32_MAX) {
            m_offset = UINT32_MAX;
        } else {
            m_offset = static_cast<uint32_t>(m_offsetActual);
        }
        if (m_diskNumStartActual > UINT16_MAX) {
            m_diskNumStart = UINT16_MAX;
        } else {
            m_diskNumStart = static_cast<uint16_t>(m_diskNumStartActual);
        }

        // version needed must be >= ZIP64_VERSION_NEEDED for ZIP64
        if (m_versionExtra < Zip64ExtendedInfo::ZIP64_VERSION_NEEDED) {
            m_versionExtra = Zip64ExtendedInfo::ZIP64_VERSION_NEEDED;
        }

        // Rebuild or create Zip64 Extended Info with actual values
        Zip64ExtendedInfo newInfo(m_compressedSizeActual, m_unCompressedSizeActual,
                                   m_offsetActual, m_diskNumStartActual);
        m_zip64ExtendedInfo = newInfo;

        // Rebuild extra field: keep non-ZIP64 parts + new Zip64 Extended Info
        if (!RebuildExtraField(true)) {
            return false;
        }
    } else {
        // ZIP32 output: use actual values, remove Zip64 Extended Info from extra field
        m_compressedSize = static_cast<uint32_t>(m_compressedSizeActual);
        m_unCompressedSize = static_cast<uint32_t>(m_unCompressedSizeActual);
        m_offset = static_cast<uint32_t>(m_offsetActual);
        m_diskNumStart = static_cast<uint16_t>(m_diskNumStartActual);
        m_zip64ExtendedInfo = std::nullopt;

        // Rebuild extra field: strip Zip64 Extended Info
        if (!RebuildExtraField(false)) {
            return false;
        }
    }
    return true;
}

bool CentralDirectory::UpdateZip64OffsetAndRebuild(uint64_t newOffset)
{
    m_offsetActual = newOffset;
    if (newOffset > UINT32_MAX) {
        m_offset = UINT32_MAX;
    } else {
        m_offset = static_cast<uint32_t>(newOffset);
    }

    if (!m_zip64ExtendedInfo.has_value()) {
        bool needsZip64 = (m_compressedSizeActual > UINT32_MAX) ||
                          (m_unCompressedSizeActual > UINT32_MAX) ||
                          (newOffset > UINT32_MAX) ||
                          (m_diskNumStartActual > UINT16_MAX);
        if (needsZip64) {
            m_zip64ExtendedInfo.emplace(m_compressedSizeActual, m_unCompressedSizeActual,
                                        newOffset, m_diskNumStartActual);
            m_isZip64 = true;
        }
    }

    if (m_zip64ExtendedInfo.has_value()) {
        m_zip64ExtendedInfo->SetLocalHeaderOffset(newOffset);
        if (!RebuildExtraField(true)) {
            return false;
        }
    }
    return true;
}

bool CentralDirectory::RebuildExtraField(bool includeZip64)
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
        int32_t subFieldLen = Zip64ExtendedInfo::EXTRA_SUBFIELD_HEADER_SIZE + dataSize;
        if (pos + subFieldLen > extraLen) {
            break;
        }
        if (headerId != Zip64ExtendedInfo::HEADER_ID) {
            newExtra.append(m_extraData, pos, subFieldLen);
        }
        pos += subFieldLen;
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
    m_length = CD_LENGTH + m_fileNameLength + m_extraLength + m_commentLength;
    return true;
}

int CentralDirectory::GetCdLength()
{
    return CD_LENGTH;
}

int CentralDirectory::GetSIGNATURE()
{
    return SIGNATURE;
}

short CentralDirectory::GetVersion()
{
    return m_version;
}

void CentralDirectory::SetVersion(short version)
{
    m_version = version;
}

short CentralDirectory::GetVersionExtra()
{
    return m_versionExtra;
}

void CentralDirectory::SetVersionExtra(short versionExtra)
{
    m_versionExtra = versionExtra;
}

short CentralDirectory::GetFlag()
{
    return m_flag;
}

void CentralDirectory::SetFlag(short flag)
{
    m_flag = flag;
}

short CentralDirectory::GetMethod()
{
    return m_method;
}

void CentralDirectory::SetMethod(short method)
{
    m_method = method;
}

short CentralDirectory::GetLastTime()
{
    return m_lastTime;
}

void CentralDirectory::SetLastTime(short lastTime)
{
    m_lastTime = lastTime;
}

short CentralDirectory::GetLastDate()
{
    return m_lastDate;
}

void CentralDirectory::SetLastDate(short lastDate)
{
    m_lastDate = lastDate;
}

int CentralDirectory::GetCrc32()
{
    return m_crc32;
}

void CentralDirectory::SetCrc32(int crc32)
{
    m_crc32 = crc32;
}

uint32_t CentralDirectory::GetCompressedSize()
{
    return m_compressedSize;
}

void CentralDirectory::SetCompressedSize(uint32_t compressedSize)
{
    m_compressedSize = compressedSize;
}

uint32_t CentralDirectory::GetUnCompressedSize()
{
    return m_unCompressedSize;
}

void CentralDirectory::SetUnCompressedSize(uint32_t unCompressedSize)
{
    m_unCompressedSize = unCompressedSize;
}

uint16_t CentralDirectory::GetFileNameLength()
{
    return m_fileNameLength;
}

void CentralDirectory::SetFileNameLength(uint16_t fileNameLength)
{
    m_fileNameLength = fileNameLength;
}

uint16_t CentralDirectory::GetExtraLength()
{
    return m_extraLength;
}

void CentralDirectory::SetExtraLength(uint16_t extraLength)
{
    m_extraLength = extraLength;
}

uint16_t CentralDirectory::GetCommentLength()
{
    return m_commentLength;
}

void CentralDirectory::SetCommentLength(uint16_t commentLength)
{
    m_commentLength = commentLength;
}

uint16_t CentralDirectory::GetDiskNumStart()
{
    return m_diskNumStart;
}

void CentralDirectory::SetDiskNumStart(uint16_t diskNumStart)
{
    m_diskNumStart = diskNumStart;
}

short CentralDirectory::GetInternalFile()
{
    return m_internalFile;
}

void CentralDirectory::SetInternalFile(short internalFile)
{
    m_internalFile = internalFile;
}

int CentralDirectory::GetExternalFile()
{
    return m_externalFile;
}

void CentralDirectory::SetExternalFile(int externalFile)
{
    m_externalFile = externalFile;
}

uint32_t CentralDirectory::GetOffset()
{
    return m_offset;
}

void CentralDirectory::SetOffset(uint32_t offset)
{
    m_offset = offset;
}

std::string CentralDirectory::GetFileName()
{
    return m_fileName;
}

void CentralDirectory::SetFileName(const std::string& fileName)
{
    m_fileName = fileName;
}

std::string CentralDirectory::GetExtraData() const
{
    return m_extraData;
}

void CentralDirectory::SetExtraData(const std::string& extraData)
{
    m_extraData = extraData;
}

std::string CentralDirectory::GetComment()
{
    return m_comment;
}

void CentralDirectory::SetComment(const std::string& comment)
{
    m_comment = comment;
}

uint32_t CentralDirectory::GetLength()
{
    return m_length;
}

void CentralDirectory::SetLength(uint32_t length)
{
    m_length = length;
}

uint64_t CentralDirectory::GetCompressedSizeActual()
{
    return m_compressedSizeActual;
}

void CentralDirectory::SetCompressedSizeActual(uint64_t compressedSize)
{
    m_compressedSizeActual = compressedSize;
}

uint64_t CentralDirectory::GetUnCompressedSizeActual()
{
    return m_unCompressedSizeActual;
}

void CentralDirectory::SetUnCompressedSizeActual(uint64_t unCompressedSize)
{
    m_unCompressedSizeActual = unCompressedSize;
}

uint64_t CentralDirectory::GetOffsetActual()
{
    return m_offsetActual;
}

void CentralDirectory::SetOffsetActual(uint64_t offset)
{
    m_offsetActual = offset;
}

uint32_t CentralDirectory::GetDiskNumStartActual()
{
    return m_diskNumStartActual;
}

void CentralDirectory::SetDiskNumStartActual(uint32_t diskNumStart)
{
    m_diskNumStartActual = diskNumStart;
}

bool CentralDirectory::IsZip64()
{
    return m_isZip64;
}

void CentralDirectory::SetIsZip64(bool isZip64)
{
    m_isZip64 = isZip64;
}

void CentralDirectory::SetZip64ExtendedInfo(const std::optional<Zip64ExtendedInfo>& info)
{
    m_zip64ExtendedInfo = info;
}
} // namespace SignatureTools
} // namespace OHOS