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

#include "zip64_end_of_central_directory_locator.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

std::optional<Zip64EndOfCentralDirectoryLocator> Zip64EndOfCentralDirectoryLocator::GetByBytes(
    const std::string& bytes, int32_t offset)
{
    if (offset < 0 || static_cast<size_t>(offset) + ZIP64_EOCD_LOCATOR_LENGTH > bytes.size()) {
        SIGNATURE_TOOLS_LOGE("bytes size %zu is too small for zip64 eocd locator (offset=%d)", bytes.size(), offset);
        return std::nullopt;
    }

    ByteBuffer bf(bytes.c_str() + offset, bytes.size() - offset);

    uint32_t signatureValue;
    if (!bf.GetUInt32(signatureValue) || signatureValue != SIGNATURE) {
        SIGNATURE_TOOLS_LOGE("zip64 eocd locator signature mismatch: 0x%08x", signatureValue);
        return std::nullopt;
    }

    Zip64EndOfCentralDirectoryLocator locator;

    uint32_t diskNumberWithZip64EocdStart;
    if (!bf.GetUInt32(diskNumberWithZip64EocdStart)) {
        SIGNATURE_TOOLS_LOGE("get disk number with zip64 eocd start failed");
        return std::nullopt;
    }
    locator.SetDiskNumberWithZip64EocdStart(diskNumberWithZip64EocdStart);

    uint64_t zip64EocdOffset;
    if (!bf.GetUInt64(zip64EocdOffset)) {
        SIGNATURE_TOOLS_LOGE("get zip64 eocd offset failed");
        return std::nullopt;
    }
    locator.SetZip64EocdOffset(zip64EocdOffset);

    uint32_t totalDiskCount;
    if (!bf.GetUInt32(totalDiskCount)) {
        SIGNATURE_TOOLS_LOGE("get total disk count failed");
        return std::nullopt;
    }
    locator.SetTotalDiskCount(totalDiskCount);

    return locator;
}

std::string Zip64EndOfCentralDirectoryLocator::ToBytes() const
{
    ByteBuffer bf(ZIP64_EOCD_LOCATOR_LENGTH);
    bf.PutUInt32(SIGNATURE);
    bf.PutUInt32(m_diskNumberWithZip64EocdStart);
    bf.PutUInt64(m_zip64EocdOffset);
    bf.PutUInt32(m_totalDiskCount);
    bf.Flip();
    return std::string(bf.GetBufferPtr(), bf.GetLimit());
}

uint32_t Zip64EndOfCentralDirectoryLocator::GetDiskNumberWithZip64EocdStart() const
{
    return m_diskNumberWithZip64EocdStart;
}

void Zip64EndOfCentralDirectoryLocator::SetDiskNumberWithZip64EocdStart(uint32_t diskNumber)
{
    m_diskNumberWithZip64EocdStart = diskNumber;
}

uint64_t Zip64EndOfCentralDirectoryLocator::GetZip64EocdOffset() const
{
    return m_zip64EocdOffset;
}

void Zip64EndOfCentralDirectoryLocator::SetZip64EocdOffset(uint64_t offset)
{
    m_zip64EocdOffset = offset;
}

uint32_t Zip64EndOfCentralDirectoryLocator::GetTotalDiskCount() const
{
    return m_totalDiskCount;
}

void Zip64EndOfCentralDirectoryLocator::SetTotalDiskCount(uint32_t count)
{
    m_totalDiskCount = count;
}

} // namespace SignatureTools
} // namespace OHOS
