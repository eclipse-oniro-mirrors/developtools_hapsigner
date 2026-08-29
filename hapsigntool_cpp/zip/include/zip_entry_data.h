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

#ifndef SIGNATRUETOOLS_ZIP_ENTRY_DATA_H
#define SIGNATRUETOOLS_ZIP_ENTRY_DATA_H

#include <string>

#include "data_descriptor.h"
#include "zip_entry_header.h"

namespace OHOS {
namespace SignatureTools {

class ZipEntryData {
public:
    /* data descriptor has or not mask */
    static constexpr short HAS_DATA_DESCRIPTOR_MASK = 0x08;

    /* data descriptor has or not flag mask */
    static constexpr short NOT_HAS_DATA_DESCRIPTOR_FLAG = 0;

    ZipEntryData()
    {
        m_zipEntryHeader = nullptr;
        m_dataDescriptor = nullptr;
    }

    ~ZipEntryData()
    {
        delete m_zipEntryHeader;
        delete m_dataDescriptor;
    }

    ZipEntryHeader* GetZipEntryHeader();

    /**
     * init zip entry by file
     *
     * @param file zip file
     * @param entryOffset entry start offset
     * @param fileSize compress file size
     * @return zip entry
     * @throws IOException read zip exception
     */
    static ZipEntryData* GetZipEntry(std::ifstream& input, uint64_t entryOffset, uint64_t fileSize);

    void SetZipEntryHeader(ZipEntryHeader* zipEntryHeader);

    DataDescriptor* GetDataDescriptor();

    void SetDataDescriptor(DataDescriptor* dataDescriptor);

    uint64_t GetFileOffset();

    void SetFileOffset(uint64_t fileOffset);

    uint64_t GetFileSize();

    void SetFileSize(uint64_t fileSize);

    uint64_t GetLength();

    void SetLength(uint64_t length);

private:
    static bool ReadEntryFileNameAndExtraByOffset(std::ifstream& input, ZipEntryHeader* entryHeader,
        uint64_t& offset);

    ZipEntryHeader* m_zipEntryHeader;

    uint64_t m_fileOffset = 0;

    uint64_t m_fileSize = 0;

    DataDescriptor* m_dataDescriptor;

    uint64_t m_length = 0;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_ZIP_ENTRY_DATA_H