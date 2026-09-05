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

#ifndef SIGNATRUETOOLS_ZIP64_ENDOF_CENTRAL_DIRECTORY_LOCATOR_H
#define SIGNATRUETOOLS_ZIP64_ENDOF_CENTRAL_DIRECTORY_LOCATOR_H

#include <optional>
#include <string>

#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {
/**
 * resolve zip Zip64 End of Central Directory Locator data
 * Zip64 End of Central Directory Locator format for:
 * zip64 end of central dir locator signature  4 bytes  (0x07064b50)
 * number of the disk with the start            4 bytes
 *   of the zip64 end of central directory
 * relative offset of the zip64                 8 bytes
 *   end of central directory record
 * total number of disks                        4 bytes
 */
class Zip64EndOfCentralDirectoryLocator {
public:
    static constexpr int ZIP64_EOCD_LOCATOR_LENGTH = 20;
    static constexpr uint32_t SIGNATURE = 0x07064b50;

    Zip64EndOfCentralDirectoryLocator() = default;
    ~Zip64EndOfCentralDirectoryLocator() = default;

    static std::optional<Zip64EndOfCentralDirectoryLocator> GetByBytes(const std::string& bytes, int32_t offset = 0);
    std::string ToBytes() const;

    uint32_t GetDiskNumberWithZip64EocdStart() const;
    void SetDiskNumberWithZip64EocdStart(uint32_t diskNumber);
    uint64_t GetZip64EocdOffset() const;
    void SetZip64EocdOffset(uint64_t offset);
    uint32_t GetTotalDiskCount() const;
    void SetTotalDiskCount(uint32_t count);

private:
    uint32_t m_diskNumberWithZip64EocdStart = 0;
    uint64_t m_zip64EocdOffset = 0;
    uint32_t m_totalDiskCount = 1;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATRUETOOLS_ZIP64_ENDOF_CENTRAL_DIRECTORY_LOCATOR_H
