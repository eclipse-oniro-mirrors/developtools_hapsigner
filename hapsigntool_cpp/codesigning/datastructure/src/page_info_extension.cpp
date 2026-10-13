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
#include "page_info_extension.h"
#include "byte_buffer.h"
#include "securec.h"
#include "signature_tools_log.h"
#include <cstdio>

namespace OHOS {
namespace SignatureTools {

static const int32_t SIGNATURE_ALIGNMENT = 4;

PageInfoExtension::PageInfoExtension(int64_t mapOffset, int64_t mapSize)
    : Extension(PAGE_INFO_INLINED, PAGE_INFO_EXTENSION_DATA_SIZE_WITHOUT_SIGN)
{
    this->mapOffset = mapOffset;
    this->mapSize = mapSize;
    this->unitSize = DEFAULT_UNIT_SIZE;
    memset_s(reserved, sizeof(reserved), 0, sizeof(reserved));
    this->signSize = 0;
}

int32_t PageInfoExtension::GetSize()
{
    return Extension::EXTENSION_HEADER_SIZE + PAGE_INFO_EXTENSION_DATA_SIZE_WITHOUT_SIGN
        + signSize + static_cast<int32_t>(zeroPadding.size());
}

void PageInfoExtension::SetSignature(const std::vector<int8_t>& signature)
{
    if (!signature.empty()) {
        this->signSize = static_cast<int32_t>(signature.size());
        this->signature = signature;
        int32_t padSize = (SIGNATURE_ALIGNMENT - (signSize % SIGNATURE_ALIGNMENT)) % SIGNATURE_ALIGNMENT;
        this->zeroPadding = std::vector<int8_t>(padSize, 0);
    }
    SetSize(GetSize() - Extension::EXTENSION_HEADER_SIZE);
}

void PageInfoExtension::ToByteArray(std::vector<int8_t>& ret)
{
    int32_t totalSize = GetSize();
    std::unique_ptr<ByteBuffer> bf = std::make_unique<ByteBuffer>(ByteBuffer(totalSize));
    std::vector<int8_t> empt(totalSize);
    bf->PutData(empt.data(), empt.size());
    bf->Clear();
    bf->PutInt32(type);
    bf->PutInt32(size);
    bf->PutInt64(mapOffset);
    bf->PutInt64(mapSize);
    bf->PutByte(unitSize);
    bf->PutByte(reserved[0]);
    bf->PutByte(reserved[1]);
    bf->PutByte(reserved[2]);
    bf->PutInt32(signSize);
    if (!signature.empty()) {
        bf->PutData(signature.data(), signature.size());
    }
    if (!zeroPadding.empty()) {
        bf->PutData(zeroPadding.data(), zeroPadding.size());
    }
    bf->Flip();
    ret = std::vector<int8_t>(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetCapacity());
}

std::string PageInfoExtension::ToString() const
{
    int32_t totalSize = Extension::EXTENSION_HEADER_SIZE + PAGE_INFO_EXTENSION_DATA_SIZE_WITHOUT_SIGN
        + signSize + static_cast<int32_t>(zeroPadding.size());
    char buf[256] = { 0 };
    snprintf_s(buf, sizeof(buf), sizeof(buf) - 1,
        "PageInfoExtension: size[%d], mapOffset[%lld], mapSize[%lld], unitSize[%d], signSize[%d]",
        totalSize, static_cast<long long>(mapOffset), static_cast<long long>(mapSize),
        static_cast<int>(unitSize), static_cast<int>(signSize));
    return std::string(buf);
}

PageInfoExtension* PageInfoExtension::FromByteArray(std::vector<int8_t>& data)
{
    if (data.size() < PAGE_INFO_EXTENSION_DATA_SIZE_WITHOUT_SIGN) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "The page info extension data is too short.");
        return nullptr;
    }
    std::unique_ptr<ByteBuffer> bf = std::make_unique<ByteBuffer>(ByteBuffer(data.size()));
    bf->PutData(data.data(), data.size());
    bf->Flip();
    int64_t inMapOffset = 0;
    if (!bf->GetInt64(inMapOffset)) {
        return nullptr;
    }
    int64_t inMapSize = 0;
    if (!bf->GetInt64(inMapSize)) {
        return nullptr;
    }
    int8_t inUnitSize = 0;
    if (!bf->GetInt8(inUnitSize)) {
        return nullptr;
    }
    int8_t inReserved[3] = { 0 };
    bf->GetByte(inReserved, sizeof(inReserved));
    int32_t inSignSize = 0;
    if (!bf->GetInt32(inSignSize) || inSignSize < 0) {
        return nullptr;
    }
    PageInfoExtension* ext = new PageInfoExtension(inMapOffset, inMapSize);
    ext->unitSize = inUnitSize;
    if (inSignSize > 0 && static_cast<size_t>(inSignSize) <= data.size() - bf->GetPosition()) {
        std::vector<int8_t> inSignature(inSignSize, 0);
        bf->GetByte(inSignature.data(), inSignSize);
        ext->SetSignature(inSignature);
    }
    SIGNATURE_TOOLS_LOGI("%s", ext->ToString().c_str());
    return ext;
}

} // namespace SignatureTools
} // namespace OHOS
