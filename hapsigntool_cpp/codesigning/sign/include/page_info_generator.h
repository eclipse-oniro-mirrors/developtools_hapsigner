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
#ifndef SIGNATURETOOLS_PAGE_INFO_GENERATOR_H
#define SIGNATURETOOLS_PAGE_INFO_GENERATOR_H

#include <fstream>
#include <string>
#include <vector>
#include <cstdint>

#include "zip_signer.h"

namespace OHOS {
namespace SignatureTools {

class PageInfoGenerator {
public:
    PageInfoGenerator(ZipSigner& zip, std::ifstream& input);
    ~PageInfoGenerator() = default;

    std::vector<int8_t> GenerateBitMap();

private:
    struct ExcSegment {
        uint8_t type;
        int64_t startOffset;
        int64_t endOffset;
    };

    void CollectRunnableFiles(ZipSigner& zip);
    void LibExecSegment(const std::string& fileName, int64_t entryDataOffset,
                        uint64_t fileOffset, uint64_t fileSize);
    bool ParseElfExecSegments(const std::vector<int8_t>& content, int64_t entryDataOffset);

    static constexpr uint8_t ELF_M_CODE = 1;
    static constexpr uint8_t ABC_M_CODE = 2;
    static constexpr int PF_X_FLAG = 0x1;
    static constexpr int MIN_ELF64_HEADER_SIZE = 64;
    static constexpr uint8_t ELFCLASS64 = 2;
    static constexpr int ELF64_E_PHOFF_OFFSET = 32;
    static constexpr int ELF64_E_PHENTSIZE_OFFSET = 54;
    static constexpr int ELF64_E_PHNUM_OFFSET = 56;
    static constexpr int ELF64_PH_FLAGS_OFFSET = 4;
    static constexpr int ELF64_PH_OFFSET_OFFSET = 8;
    static constexpr int ELF64_PH_FILESZ_OFFSET = 32;
    static constexpr int PAGE_SHIFT_4K = 12;
    static constexpr int BITS_PER_LONG = 64;

    std::ifstream& m_input;
    int64_t m_maxEntryDataOffset = 0;
    std::vector<ExcSegment> m_excSegmentList;
};

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_PAGE_INFO_GENERATOR_H
