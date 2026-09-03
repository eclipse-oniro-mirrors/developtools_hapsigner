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

#include "zip64_extended_info.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

int32_t Zip64ExtendedInfo::FindZip64Header(const std::string& extraData)
{
    int32_t pos = 0;
    int32_t extraLen = static_cast<int32_t>(extraData.size());

    while (pos + EXTRA_SUBFIELD_HEADER_SIZE <= extraLen) {
        uint16_t headerId = static_cast<uint8_t>(extraData[pos]) |
                            (static_cast<uint16_t>(static_cast<uint8_t>(extraData[pos + 1])) << 8);
        uint16_t dataSize = static_cast<uint8_t>(extraData[pos + 2]) |
                            (static_cast<uint16_t>(static_cast<uint8_t>(extraData[pos + 3])) << 8);
        int32_t subFieldLen = EXTRA_SUBFIELD_HEADER_SIZE + dataSize;
        if (pos + subFieldLen > extraLen) {
            break;
        }
        if (headerId == HEADER_ID) {
            return pos;
        }
        pos += subFieldLen;
    }
    return -1;
}

bool Zip64ExtendedInfo::ReadFields(ByteBuffer& bf)
{
    if (m_hasUnCompressedSize) {
        uint64_t value;
        if (!bf.GetUInt64(value)) {
            SIGNATURE_TOOLS_LOGE("get unCompressedSize from zip64 extended info failed");
            return false;
        }
        m_unCompressedSize = value;
    }

    if (m_hasCompressedSize) {
        uint64_t value;
        if (!bf.GetUInt64(value)) {
            SIGNATURE_TOOLS_LOGE("get compressedSize from zip64 extended info failed");
            return false;
        }
        m_compressedSize = value;
    }

    if (m_hasLocalHeaderOffset) {
        uint64_t value;
        if (!bf.GetUInt64(value)) {
            SIGNATURE_TOOLS_LOGE("get localHeaderOffset from zip64 extended info failed");
            return false;
        }
        m_localHeaderOffset = value;
    }

    if (m_hasDiskNumStart) {
        uint32_t value;
        if (!bf.GetUInt32(value)) {
            SIGNATURE_TOOLS_LOGE("get diskNumStart from zip64 extended info failed");
            return false;
        }
        m_diskNumStart = value;
    }
    return true;
}

std::optional<Zip64ExtendedInfo> Zip64ExtendedInfo::Parse(const std::string& extraData,
    uint32_t compressedSize, uint32_t unCompressedSize,
    uint32_t localHeaderOffset, uint16_t diskNumStart)
{
    Zip64ExtendedInfo info;
    info.m_hasCompressedSize = (compressedSize == UINT32_SENTINEL);
    info.m_hasUnCompressedSize = (unCompressedSize == UINT32_SENTINEL);
    info.m_hasLocalHeaderOffset = (localHeaderOffset == UINT32_SENTINEL);
    info.m_hasDiskNumStart = (diskNumStart == UINT16_SENTINEL);

    if (!info.m_hasCompressedSize && !info.m_hasUnCompressedSize &&
        !info.m_hasLocalHeaderOffset && !info.m_hasDiskNumStart) {
        return std::nullopt;
    }

    int32_t pos = FindZip64Header(extraData);
    if (pos < 0) {
        return std::nullopt;
    }

    // Skip header ID and data size (EXTRA_SUBFIELD_HEADER_SIZE bytes)
    int32_t dataOffset = pos + EXTRA_SUBFIELD_HEADER_SIZE;
    int32_t extraLen = static_cast<int32_t>(extraData.size());
    ByteBuffer bf(extraData.c_str() + dataOffset, extraLen - dataOffset);

    if (!info.ReadFields(bf)) {
        return std::nullopt;
    }
    return info;
}

Zip64ExtendedInfo::Zip64ExtendedInfo(uint64_t compressedSize, uint64_t unCompressedSize,
                                     uint64_t localHeaderOffset, uint32_t diskNumStart)
{
    m_compressedSize = compressedSize;
    m_unCompressedSize = unCompressedSize;
    m_localHeaderOffset = localHeaderOffset;
    m_diskNumStart = diskNumStart;

    m_hasCompressedSize = (compressedSize > UINT32_SENTINEL);
    m_hasUnCompressedSize = (unCompressedSize > UINT32_SENTINEL);
    m_hasLocalHeaderOffset = (localHeaderOffset > UINT32_SENTINEL);
    m_hasDiskNumStart = (diskNumStart > UINT16_SENTINEL);
}

std::string Zip64ExtendedInfo::ToBytes() const
{
    // If no fields overflow, don't output Zip64 Extended Info
    if (!m_hasCompressedSize && !m_hasUnCompressedSize &&
        !m_hasLocalHeaderOffset && !m_hasDiskNumStart) {
        return "";
    }

    uint16_t dataSize = ComputeDataSize();
    int32_t totalSize = EXTRA_SUBFIELD_HEADER_SIZE + dataSize;
    ByteBuffer bf(totalSize);
    bf.PutUInt16(HEADER_ID);
    bf.PutUInt16(dataSize);

    if (m_hasUnCompressedSize) {
        bf.PutUInt64(m_unCompressedSize);
    }
    if (m_hasCompressedSize) {
        bf.PutUInt64(m_compressedSize);
    }
    if (m_hasLocalHeaderOffset) {
        bf.PutUInt64(m_localHeaderOffset);
    }
    if (m_hasDiskNumStart) {
        bf.PutUInt32(m_diskNumStart);
    }

    bf.Flip();
    return std::string(bf.GetBufferPtr(), bf.GetLimit());
}

uint16_t Zip64ExtendedInfo::ComputeDataSize() const
{
    uint16_t size = 0;
    if (m_hasUnCompressedSize) {
        size += sizeof(uint64_t); // 8
    }
    if (m_hasCompressedSize) {
        size += sizeof(uint64_t); // 8
    }
    if (m_hasLocalHeaderOffset) {
        size += sizeof(uint64_t); // 8
    }
    if (m_hasDiskNumStart) {
        size += sizeof(uint32_t); // 4
    }
    return size;
}

bool Zip64ExtendedInfo::HasCompressedSize() const
{
    return m_hasCompressedSize;
}

bool Zip64ExtendedInfo::HasUnCompressedSize() const
{
    return m_hasUnCompressedSize;
}

bool Zip64ExtendedInfo::HasLocalHeaderOffset() const
{
    return m_hasLocalHeaderOffset;
}

bool Zip64ExtendedInfo::HasDiskNumStart() const
{
    return m_hasDiskNumStart;
}

uint64_t Zip64ExtendedInfo::GetCompressedSize() const
{
    return m_compressedSize;
}

void Zip64ExtendedInfo::SetCompressedSize(uint64_t size)
{
    m_compressedSize = size;
    m_hasCompressedSize = (size > UINT32_SENTINEL);
}

uint64_t Zip64ExtendedInfo::GetUnCompressedSize() const
{
    return m_unCompressedSize;
}

void Zip64ExtendedInfo::SetUnCompressedSize(uint64_t size)
{
    m_unCompressedSize = size;
    m_hasUnCompressedSize = (size > UINT32_SENTINEL);
}

uint64_t Zip64ExtendedInfo::GetLocalHeaderOffset() const
{
    return m_localHeaderOffset;
}

void Zip64ExtendedInfo::SetLocalHeaderOffset(uint64_t offset)
{
    m_localHeaderOffset = offset;
    m_hasLocalHeaderOffset = (offset > UINT32_SENTINEL);
}

uint32_t Zip64ExtendedInfo::GetDiskNumStart() const
{
    return m_diskNumStart;
}

void Zip64ExtendedInfo::SetDiskNumStart(uint32_t diskNum)
{
    m_diskNumStart = diskNum;
    m_hasDiskNumStart = (diskNum > UINT16_SENTINEL);
}

bool Zip64ExtendedInfo::IsZip64Needed() const
{
    return m_hasCompressedSize || m_hasUnCompressedSize ||
           m_hasLocalHeaderOffset || m_hasDiskNumStart;
}

} // namespace SignatureTools
} // namespace OHOS
