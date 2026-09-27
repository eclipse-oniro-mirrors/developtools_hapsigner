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
#ifndef SIGNATRUETOOLS_TICKET_STAPLE_H
#define SIGNATRUETOOLS_TICKET_STAPLE_H

#include <string>
#include <fstream>

#include "options.h"
#include "byte_buffer.h"
#include "signature_info.h"
#include "random_access_file.h"
#include "zip64_end_of_central_directory.h"
#include "zip64_end_of_central_directory_locator.h"

namespace OHOS {
namespace SignatureTools {

class TicketStaple {
public:
    TicketStaple() = delete;
    static bool StapleApp(Options* options);

private:
    struct StapleContext {
        SignatureInfo signInfo;
        ByteBuffer originalSigningBlock;
        int64_t centralDirSize = 0;
        bool isZip64 = false;
        ByteBuffer hapEocd;
        Zip64EndOfCentralDirectory zip64Eocd;
        Zip64EndOfCentralDirectoryLocator zip64Locator;
        ByteBuffer newSigningBlock;
    };

    static bool ExtractStapleInfo(const std::string& inFile, StapleContext& ctx);
    static bool ReadZip64Eocd(RandomAccessFile& inputFile, int64_t eocdOffset, StapleContext& ctx);
    static bool ModifyStapleData(StapleContext& ctx, const ByteBuffer& ticketData);
    static bool RebuildSigningBlock(StapleContext& ctx, const std::string& newPkcs7Der,
        int64_t& newSigningBlockSize);
    static bool UpdateZipMetadata(StapleContext& ctx, int64_t newSigningBlockSize);
    static bool WriteStapleOutput(const std::string& backupFile, const std::string& tmpFile,
        StapleContext& ctx);
    static bool CopyFileRange(RandomAccessFile& inputFile, std::ofstream& output,
        int64_t offset, int64_t size, const std::string& errMsg);
};

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_TICKET_STAPLE_H
