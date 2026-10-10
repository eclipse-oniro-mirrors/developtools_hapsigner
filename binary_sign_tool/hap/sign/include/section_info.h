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

#ifndef SIGNATURETOOLS_SECTION_INFO_H
#define SIGNATURETOOLS_SECTION_INFO_H

#include <cstdint>
#include <string>
#include <vector>
#include <elfio.hpp>

namespace OHOS {
namespace SignatureTools {

class SectionInfo {
public:
    SectionInfo() = default;
    ~SectionInfo() = default;

    int GetIndex() const { return index; }
    void SetIndex(int idx) { index = idx; }

    ELFIO::Elf_Word GetNameOffset() const { return nameOffset; }
    void SetNameOffset(ELFIO::Elf_Word off) { nameOffset = off; }

    ELFIO::Elf_Word GetType() const { return type; }
    void SetType(ELFIO::Elf_Word t) { type = t; }

    ELFIO::Elf_Xword GetFlags() const { return flags; }
    void SetFlags(ELFIO::Elf_Xword f) { flags = f; }

    ELFIO::Elf64_Addr GetAddress() const { return address; }
    void SetAddress(ELFIO::Elf64_Addr addr) { address = addr; }

    ELFIO::Elf64_Off GetOffset() const { return offset; }
    void SetOffset(ELFIO::Elf64_Off off) { offset = off; }

    ELFIO::Elf_Xword GetSize() const { return size; }
    void SetSize(ELFIO::Elf_Xword s) { size = s; }

    ELFIO::Elf_Word GetLink() const { return link; }
    void SetLink(ELFIO::Elf_Word l) { link = l; }

    ELFIO::Elf_Word GetInfo() const { return info; }
    void SetInfo(ELFIO::Elf_Word i) { info = i; }

    ELFIO::Elf_Xword GetAddrAlign() const { return addrAlign; }
    void SetAddrAlign(ELFIO::Elf_Xword a) { addrAlign = a; }

    ELFIO::Elf_Xword GetEntSize() const { return entSize; }
    void SetEntSize(ELFIO::Elf_Xword e) { entSize = e; }

    const std::string& GetNameString() const { return nameString; }
    void SetNameString(const std::string& name) { nameString = name; }

    const std::vector<uint8_t>& GetData() const { return data; }
    void SetData(const std::vector<uint8_t>& d) { data = d; }
    void SetData(const char* raw, size_t len);
    bool HasData() const { return !data.empty(); }

    bool IsNew() const { return isNew; }
    void SetNew(bool flag) { isNew = flag; }

    SectionInfo DeepCopy() const;
    std::string ToBuffer(bool is64, const std::shared_ptr<ELFIO::endianess_convertor>& convertor,
                        int entrySize) const;

private:
    int index = 0;
    ELFIO::Elf_Word nameOffset = 0;
    ELFIO::Elf_Word type = 0;
    ELFIO::Elf_Xword flags = 0;
    ELFIO::Elf64_Addr address = 0;
    ELFIO::Elf64_Off offset = 0;
    ELFIO::Elf_Xword size = 0;
    ELFIO::Elf_Word link = 0;
    ELFIO::Elf_Word info = 0;
    ELFIO::Elf_Xword addrAlign = 0;
    ELFIO::Elf_Xword entSize = 0;
    std::string nameString;
    std::vector<uint8_t> data;
    bool isNew = false;
};

} // namespace SignatureTools
} // namespace OHOS

#endif // SIGNATURETOOLS_SECTION_INFO_H
