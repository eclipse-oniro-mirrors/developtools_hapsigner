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

#include <cinttypes>
#include <algorithm>
#include <stdexcept>
#include <string>

#include "zip_utils.h"

namespace OHOS {
namespace SignatureTools {
bool ZipUtils::SetCentralDirectoryOffset(ByteBuffer& eocd, int64_t offset)
{
    return SetCentralDirectoryOffset(eocd, offset, nullptr);
}

bool ZipUtils::SetCentralDirectoryOffset(ByteBuffer& eocd, int64_t offset,
    Zip64EndOfCentralDirectory* zip64Eocd)
{
    if (offset > UINT32_MAX_VALUE) {
        // Offset overflows 32 bits: Zip64 EOCD is required to store the actual value
        if (zip64Eocd == nullptr) {
            SIGNATURE_TOOLS_LOGE("Set Central Directory Offset failed: offset %" PRId64
                " overflows UINT32_MAX but no Zip64 EOCD provided", offset);
            return false;
        }
        // ZIP64: write sentinel value in EOCD32 and actual value in Zip64 EOCD
        if (!SetUInt32ToBuffer(eocd, eocd.GetPosition() + ZIP_CENTRAL_DIR_OFFSET_IN_EOCD,
            static_cast<int64_t>(0xFFFFFFFF))) {
            return false;
        }
        zip64Eocd->SetOffset(static_cast<uint64_t>(offset));
        return true;
    }
    if (zip64Eocd != nullptr) {
        // ZIP64 mode: write sentinel value in EOCD32 and actual value in Zip64 EOCD
        if (!SetUInt32ToBuffer(eocd, eocd.GetPosition() + ZIP_CENTRAL_DIR_OFFSET_IN_EOCD,
            static_cast<int64_t>(0xFFFFFFFF))) {
            return false;
        }
        zip64Eocd->SetOffset(static_cast<uint64_t>(offset));
        return true;
    }
    // ZIP32 mode: write actual value directly in EOCD32
    if (!SetUInt32ToBuffer(eocd, eocd.GetPosition() + ZIP_CENTRAL_DIR_OFFSET_IN_EOCD, offset)) {
        SIGNATURE_TOOLS_LOGE("Set Central Directory Offset failed.");
        return false;
    }
    return true;
}

bool ZipUtils::SetUInt32ToBuffer(ByteBuffer& buffer, int offset, int64_t value)
{
    SIGNATURE_TOOLS_LOGI("offset: %d, value: %" PRId64 ", UINT32_MAX_VALUE: %" PRId64,
                         offset, value, UINT32_MAX_VALUE);
    if ((value < 0) || (value > UINT32_MAX_VALUE)) {
        SIGNATURE_TOOLS_LOGE("invalid_argument. value of out range: %" PRId64, value);
        return false;
    }
    buffer.PutInt32(offset, static_cast<int>(value));
    return true;
}

bool ZipUtils::SetUInt64ToBuffer(ByteBuffer& buffer, int offset, int64_t value)
{
    SIGNATURE_TOOLS_LOGI("offset: %d, value: %" PRId64, offset, value);
    if (value < 0) {
        SIGNATURE_TOOLS_LOGE("invalid_argument. negative value: %" PRId64, value);
        return false;
    }
    buffer.PutUInt64(offset, static_cast<uint64_t>(value));
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
