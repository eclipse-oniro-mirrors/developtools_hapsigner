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

#ifndef SIGNATRUETOOLS_ZIP64_ENDOF_CENTRAL_DIRECTORY_H
#define SIGNATRUETOOLS_ZIP64_ENDOF_CENTRAL_DIRECTORY_H

#include <optional>
#include <string>

#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {
/**
 * resolve zip Zip64 End of Central Directory data
 * Zip64 End of Central Directory format for:
 * zip64 end of central dir signature    4 bytes  (0x06064b50)
 * size of zip64 end of central dir      8 bytes
 * version made by                       2 bytes
 * version needed to extract             2 bytes
 * number of this disk                   4 bytes
 * number of the disk with the start     4 bytes
 *   of the central directory
 * total number of entries in the        8 bytes
 *   central directory on this disk
 * total number of entries in the        8 bytes
 *   central directory
 * size of the central directory         8 bytes
 * offset of start of central            8 bytes
 *   directory with respect to the
 *   starting disk number
 */
class Zip64EndOfCentralDirectory {
public:
    static constexpr int ZIP64_EOCD_LENGTH = 56;
    static constexpr int ZIP64_EOCD_FIXED_PART_SIZE = 12; // signature (4) + size field (8)
    static constexpr uint32_t SIGNATURE = 0x06064b50;

    Zip64EndOfCentralDirectory() = default;
    ~Zip64EndOfCentralDirectory() = default;

    static std::optional<Zip64EndOfCentralDirectory> GetByBytes(const std::string& bytes, int32_t offset = 0);
    std::string ToBytes() const;

    uint64_t GetSizeOfZip64Eocd() const;
    void SetSizeOfZip64Eocd(uint64_t size);
    uint16_t GetVersionMadeBy() const;
    void SetVersionMadeBy(uint16_t version);
    uint16_t GetVersionNeeded() const;
    void SetVersionNeeded(uint16_t version);
    uint32_t GetThisDiskNumber() const;
    void SetThisDiskNumber(uint32_t diskNumber);
    uint32_t GetDiskNumberWithCDStart() const;
    void SetDiskNumberWithCDStart(uint32_t diskNumber);
    uint64_t GetThisDiskCDNum() const;
    void SetThisDiskCDNum(uint64_t num);
    uint64_t GetCDTotal() const;
    void SetCDTotal(uint64_t total);
    uint64_t GetCDSize() const;
    void SetCDSize(uint64_t size);
    uint64_t GetOffset() const;
    void SetOffset(uint64_t offset);

private:
    static bool ReadField(ByteBuffer& bf, uint16_t& value, const char* name);
    static bool ReadField(ByteBuffer& bf, uint32_t& value, const char* name);
    static bool ReadField(ByteBuffer& bf, uint64_t& value, const char* name);

    uint64_t m_sizeOfZip64Eocd = 0;
    uint16_t m_versionMadeBy = 0;
    uint16_t m_versionNeeded = 45;
    uint32_t m_thisDiskNumber = 0;
    uint32_t m_diskNumberWithCDStart = 0;
    uint64_t m_thisDiskCDNum = 0;
    uint64_t m_cDTotal = 0;
    uint64_t m_cDSize = 0;
    uint64_t m_offset = 0;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATRUETOOLS_ZIP64_ENDOF_CENTRAL_DIRECTORY_H
