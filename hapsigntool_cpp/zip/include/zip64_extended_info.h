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

#ifndef SIGNATRUETOOLS_ZIP64_EXTENDED_INFO_H
#define SIGNATRUETOOLS_ZIP64_EXTENDED_INFO_H

#include <cstdint>
#include <optional>
#include <string>

#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {
/**
 * resolve zip Zip64 Extended Information Extra Field data
 * This extra field is used in both Local File Headers and Central Directory entries.
 *
 * Zip64 Extended Information Extra Field format:
 * header ID                            2 bytes  (0x0001)
 * data size                            2 bytes
 * original uncompressed size           8 bytes  (if original field = 0xFFFFFFFF)
 * compressed size                      8 bytes  (if original field = 0xFFFFFFFF)
 * relative header offset               8 bytes  (if original field = 0xFFFFFFFF)
 * disk start number                    4 bytes  (if original field = 0xFFFF)
 */
class Zip64ExtendedInfo {
public:
    static constexpr uint16_t HEADER_ID = 0x0001;
    static constexpr uint32_t UINT32_SENTINEL = 0xFFFFFFFF;
    static constexpr uint16_t UINT16_SENTINEL = 0xFFFF;
    static constexpr int32_t EXTRA_SUBFIELD_HEADER_SIZE = 4; // header ID (2) + data size (2)
    static constexpr uint16_t ZIP64_VERSION_NEEDED = 45;

    Zip64ExtendedInfo() = default;
    ~Zip64ExtendedInfo() = default;

    /**
     * Parse Zip64 Extended Information from extra field data.
     * The original ZIP32 field values are passed to determine which 64-bit fields are present.
     */
    static std::optional<Zip64ExtendedInfo> Parse(const std::string& extraData,
                                                   uint32_t compressedSize,
                                                   uint32_t unCompressedSize,
                                                   uint32_t localHeaderOffset,
                                                   uint16_t diskNumStart);

    /**
     * Construct for writing: specify which 64-bit values overflow the ZIP32 limits.
     * Only fields that exceed their ZIP32 limits will be included in the output.
     */
    Zip64ExtendedInfo(uint64_t compressedSize, uint64_t unCompressedSize,
                      uint64_t localHeaderOffset, uint32_t diskNumStart);

    /** Serialize to bytes for embedding in extra field */
    std::string ToBytes() const;

    /** Compute the data-size field value for the header */
    uint16_t ComputeDataSize() const;

    bool HasCompressedSize() const;
    bool HasUnCompressedSize() const;
    bool HasLocalHeaderOffset() const;
    bool HasDiskNumStart() const;
    uint64_t GetCompressedSize() const;
    void SetCompressedSize(uint64_t size);
    uint64_t GetUnCompressedSize() const;
    void SetUnCompressedSize(uint64_t size);
    uint64_t GetLocalHeaderOffset() const;
    void SetLocalHeaderOffset(uint64_t offset);
    uint32_t GetDiskNumStart() const;
    void SetDiskNumStart(uint32_t diskNum);

    /** Check if any field overflows ZIP32 limits */
    bool IsZip64Needed() const;

private:
    static int32_t FindZip64Header(const std::string& extraData);
    bool ReadFields(ByteBuffer& bf);
    bool m_hasCompressedSize = false;
    bool m_hasUnCompressedSize = false;
    bool m_hasLocalHeaderOffset = false;
    bool m_hasDiskNumStart = false;
    uint64_t m_compressedSize = 0;
    uint64_t m_unCompressedSize = 0;
    uint64_t m_localHeaderOffset = 0;
    uint32_t m_diskNumStart = 0;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATRUETOOLS_ZIP64_EXTENDED_INFO_H
