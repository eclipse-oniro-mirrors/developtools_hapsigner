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

#ifndef SIGNATRUETOOLS_ZIP_SIGNER_H
#define SIGNATRUETOOLS_ZIP_SIGNER_H

#include <fstream>
#include <string>
#include <vector>

#include "endof_central_directory.h"
#include "signature_tools_log.h"
#include "zip64_end_of_central_directory.h"
#include "zip64_end_of_central_directory_locator.h"
#include "zip_entry.h"

namespace OHOS {
namespace SignatureTools {
class ZipSigner {
public:
    /* file is uncompress file flag */
    static constexpr int FILE_UNCOMPRESS_METHOD_FLAG = 0;

    /* max comment length */
    static constexpr int MAX_COMMENT_LENGTH = 65535;

    /* 1MB size threshold for resfile alignment */
    static constexpr int ONE_MB = 1024 * 1024;

    ZipSigner()
    {
        m_endOfCentralDirectory = nullptr;
        m_zip64Eocd = nullptr;
        m_zip64EocdLocator = nullptr;
    }

    ~ZipSigner()
    {
        delete m_endOfCentralDirectory;
        delete m_zip64Eocd;
        delete m_zip64EocdLocator;
        for (auto& zipEntry : m_zipEntries) {
            delete zipEntry;
        }
    }

    bool Init(std::ifstream& inputFile);

    /**
     * output zip to zip file
     *
     * @param outFile file path
     */
    bool ToFile(std::ifstream& input, std::ofstream& output);

    /**
     * alignment uncompress entry
     *
     * @param alignment int alignment
     */
    bool Alignment(int alignment);

    bool RemoveSignBlock();

    std::vector<ZipEntry*>& GetZipEntries();

    void SetZipEntries(const std::vector<ZipEntry*>& zipEntries);

    uint64_t GetSigningOffset();

    void SetSigningOffset(uint64_t signingOffset);

    std::string GetSigningBlock();

    void SetSigningBlock(const std::string& signingBlock);

    uint64_t GetCDOffset();

    void SetCDOffset(uint64_t cDOffset);

    uint64_t GetEOCDOffset();

    void SetEOCDOffset(uint64_t eOCDOffset);

    EndOfCentralDirectory* GetEndOfCentralDirectory();

    void SetEndOfCentralDirectory(EndOfCentralDirectory* endOfCentralDirectory);

    void SetForceZip64(bool forceZip64);

private:
    EndOfCentralDirectory* GetZipEndOfCentralDirectory(std::ifstream& input);

    bool GetZipCentralDirectory(std::ifstream& input);

    std::string GetSigningBlock(std::ifstream& input);

    bool GetZipEntries(std::ifstream& input);

    /* sort uncompress entry in the front. */
    bool Sort();

    bool ResetOffset();
    bool DetermineZip64Needed();
    bool UpdateZip64OffsetsInCD();

    EndOfCentralDirectory* ParseZip64IfPresent(std::ifstream& input,
        EndOfCentralDirectory* eocd, uint64_t fileSize);
    bool ReadZip64EocdLocator(std::ifstream& input);
    bool ReadZip64Eocd(std::ifstream& input);
    bool UpdateEntriesForMode(bool zip64);
    uint64_t RecalcLengthsAndOffsets(bool useZip64Offset);
    void FillEocdAndZip64(bool needZip64);
    bool WriteZipEntries(std::ifstream& input, std::ofstream& output);
    bool WriteTrailingSections(std::ofstream& output);

    std::vector<ZipEntry*> m_zipEntries;

    uint64_t m_signingOffset = 0;

    std::string m_signingBlock;

    uint64_t m_cDOffset = 0;

    uint64_t m_eOCDOffset = 0;

    EndOfCentralDirectory* m_endOfCentralDirectory;

    bool m_isZip64 = false;

    bool m_forceZip64 = false;

    Zip64EndOfCentralDirectory* m_zip64Eocd;

    Zip64EndOfCentralDirectoryLocator* m_zip64EocdLocator;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_ZIP_SIGNER_H
