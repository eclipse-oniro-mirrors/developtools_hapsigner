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

#include "section_info.h"

#include <securec.h>

namespace OHOS {
namespace SignatureTools {

void SectionInfo::SetData(const char* raw, size_t len)
{
    if (raw == nullptr || len == 0) {
        data.clear();
        return;
    }
    data.assign(reinterpret_cast<const uint8_t*>(raw), reinterpret_cast<const uint8_t*>(raw) + len);
}

SectionInfo SectionInfo::DeepCopy() const
{
    SectionInfo copy;
    copy.index = index;
    copy.nameOffset = nameOffset;
    copy.type = type;
    copy.flags = flags;
    copy.address = address;
    copy.offset = offset;
    copy.size = size;
    copy.link = link;
    copy.info = info;
    copy.addrAlign = addrAlign;
    copy.entSize = entSize;
    copy.nameString = nameString;
    copy.data = data;
    copy.isNew = isNew;
    return copy;
}

std::string SectionInfo::ToBuffer(bool is64, const std::shared_ptr<ELFIO::endianess_convertor>& convertor,
                                  int entrySize) const
{
    std::string buf(entrySize, '\0');
    size_t pos = 0;

    auto writeWord = [&](uint32_t val) {
        val = (*convertor)(val);
        if (pos + sizeof(val) <= buf.size()) {
            if (memcpy_s(&buf[pos], buf.size() - pos, &val, sizeof(val)) != 0) {
                return;
            }
        }
        pos += sizeof(val);
    };
    auto writeXword = [&](uint64_t val) {
        val = (*convertor)(val);
        if (pos + sizeof(val) <= buf.size()) {
            if (memcpy_s(&buf[pos], buf.size() - pos, &val, sizeof(val)) != 0) {
                return;
            }
        }
        pos += sizeof(val);
    };

    writeWord(nameOffset);
    writeWord(type);
    if (is64) {
        writeXword(flags);
        writeXword(address);
        writeXword(offset);
        writeXword(size);
    } else {
        writeWord(static_cast<uint32_t>(flags));
        writeWord(static_cast<uint32_t>(address));
        writeWord(static_cast<uint32_t>(offset));
        writeWord(static_cast<uint32_t>(size));
    }
    writeWord(link);
    writeWord(info);
    if (is64) {
        writeXword(addrAlign);
        writeXword(entSize);
    } else {
        writeWord(static_cast<uint32_t>(addrAlign));
        writeWord(static_cast<uint32_t>(entSize));
    }

    return buf;
}

} // namespace SignatureTools
} // namespace OHOS
