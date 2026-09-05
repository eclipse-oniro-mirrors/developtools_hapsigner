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

#include "zip64_end_of_central_directory.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

bool Zip64EndOfCentralDirectory::ReadField(ByteBuffer& bf, uint16_t& value, const char* name)
{
    if (!bf.GetUInt16(value)) {
        SIGNATURE_TOOLS_LOGE("get %s failed", name);
        return false;
    }
    return true;
}

bool Zip64EndOfCentralDirectory::ReadField(ByteBuffer& bf, uint32_t& value, const char* name)
{
    if (!bf.GetUInt32(value)) {
        SIGNATURE_TOOLS_LOGE("get %s failed", name);
        return false;
    }
    return true;
}

bool Zip64EndOfCentralDirectory::ReadField(ByteBuffer& bf, uint64_t& value, const char* name)
{
    if (!bf.GetUInt64(value)) {
        SIGNATURE_TOOLS_LOGE("get %s failed", name);
        return false;
    }
    return true;
}

std::optional<Zip64EndOfCentralDirectory> Zip64EndOfCentralDirectory::GetByBytes(
    const std::string& bytes, int32_t offset)
{
    if (offset < 0 || static_cast<size_t>(offset) + ZIP64_EOCD_LENGTH > bytes.size()) {
        SIGNATURE_TOOLS_LOGE("bytes size %zu is too small for zip64 eocd (offset=%d)", bytes.size(), offset);
        return std::nullopt;
    }

    ByteBuffer bf(bytes.c_str() + offset, bytes.size() - offset);

    uint32_t signatureValue;
    if (!bf.GetUInt32(signatureValue) || signatureValue != SIGNATURE) {
        SIGNATURE_TOOLS_LOGE("zip64 eocd signature mismatch: 0x%08x", signatureValue);
        return std::nullopt;
    }

    Zip64EndOfCentralDirectory zip64Eocd;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    if (!ReadField(bf, u64, "size of zip64 eocd")) return std::nullopt;
    zip64Eocd.SetSizeOfZip64Eocd(u64);
    if (!ReadField(bf, u16, "version made by")) return std::nullopt;
    zip64Eocd.SetVersionMadeBy(u16);
    if (!ReadField(bf, u16, "version needed")) return std::nullopt;
    zip64Eocd.SetVersionNeeded(u16);
    if (!ReadField(bf, u32, "this disk number")) return std::nullopt;
    zip64Eocd.SetThisDiskNumber(u32);
    if (!ReadField(bf, u32, "disk number with cd start")) return std::nullopt;
    zip64Eocd.SetDiskNumberWithCDStart(u32);
    if (!ReadField(bf, u64, "this disk cd num")) return std::nullopt;
    zip64Eocd.SetThisDiskCDNum(u64);
    if (!ReadField(bf, u64, "cd total")) return std::nullopt;
    zip64Eocd.SetCDTotal(u64);
    if (!ReadField(bf, u64, "cd size")) return std::nullopt;
    zip64Eocd.SetCDSize(u64);
    if (!ReadField(bf, u64, "cd offset")) return std::nullopt;
    zip64Eocd.SetOffset(u64);

    return zip64Eocd;
}

std::string Zip64EndOfCentralDirectory::ToBytes() const
{
    ByteBuffer bf(ZIP64_EOCD_LENGTH);
    bf.PutUInt32(SIGNATURE);
    bf.PutUInt64(m_sizeOfZip64Eocd);
    bf.PutUInt16(m_versionMadeBy);
    bf.PutUInt16(m_versionNeeded);
    bf.PutUInt32(m_thisDiskNumber);
    bf.PutUInt32(m_diskNumberWithCDStart);
    bf.PutUInt64(m_thisDiskCDNum);
    bf.PutUInt64(m_cDTotal);
    bf.PutUInt64(m_cDSize);
    bf.PutUInt64(m_offset);
    bf.Flip();
    return std::string(bf.GetBufferPtr(), bf.GetLimit());
}

uint64_t Zip64EndOfCentralDirectory::GetSizeOfZip64Eocd() const
{
    return m_sizeOfZip64Eocd;
}

void Zip64EndOfCentralDirectory::SetSizeOfZip64Eocd(uint64_t size)
{
    m_sizeOfZip64Eocd = size;
}

uint16_t Zip64EndOfCentralDirectory::GetVersionMadeBy() const
{
    return m_versionMadeBy;
}

void Zip64EndOfCentralDirectory::SetVersionMadeBy(uint16_t version)
{
    m_versionMadeBy = version;
}

uint16_t Zip64EndOfCentralDirectory::GetVersionNeeded() const
{
    return m_versionNeeded;
}

void Zip64EndOfCentralDirectory::SetVersionNeeded(uint16_t version)
{
    m_versionNeeded = version;
}

uint32_t Zip64EndOfCentralDirectory::GetThisDiskNumber() const
{
    return m_thisDiskNumber;
}

void Zip64EndOfCentralDirectory::SetThisDiskNumber(uint32_t diskNumber)
{
    m_thisDiskNumber = diskNumber;
}

uint32_t Zip64EndOfCentralDirectory::GetDiskNumberWithCDStart() const
{
    return m_diskNumberWithCDStart;
}

void Zip64EndOfCentralDirectory::SetDiskNumberWithCDStart(uint32_t diskNumber)
{
    m_diskNumberWithCDStart = diskNumber;
}

uint64_t Zip64EndOfCentralDirectory::GetThisDiskCDNum() const
{
    return m_thisDiskCDNum;
}

void Zip64EndOfCentralDirectory::SetThisDiskCDNum(uint64_t num)
{
    m_thisDiskCDNum = num;
}

uint64_t Zip64EndOfCentralDirectory::GetCDTotal() const
{
    return m_cDTotal;
}

void Zip64EndOfCentralDirectory::SetCDTotal(uint64_t total)
{
    m_cDTotal = total;
}

uint64_t Zip64EndOfCentralDirectory::GetCDSize() const
{
    return m_cDSize;
}

void Zip64EndOfCentralDirectory::SetCDSize(uint64_t size)
{
    m_cDSize = size;
}

uint64_t Zip64EndOfCentralDirectory::GetOffset() const
{
    return m_offset;
}

void Zip64EndOfCentralDirectory::SetOffset(uint64_t offset)
{
    m_offset = offset;
}

} // namespace SignatureTools
} // namespace OHOS
