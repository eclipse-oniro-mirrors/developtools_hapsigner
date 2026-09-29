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
#ifndef SIGNATRUETOOLS_TICKET_VALIDATE_H
#define SIGNATRUETOOLS_TICKET_VALIDATE_H

#include <string>
#include <vector>

#include "options.h"
#include "signature_info.h"
#include "profile_info.h"
#include <contrib/minizip/unzip.h>
#include <openssl/evp.h>
#include "cJSON.h"

namespace OHOS {
namespace SignatureTools {

class TicketValidate {
public:
    TicketValidate() = delete;
    static bool ValidateStaple(Options* options);

private:
    enum TicketHashType {
        TICKET_HASH_SHA256,
        TICKET_HASH_SHA384,
        TICKET_HASH_SHA512
    };

    struct FileHashEntry {
        std::string path;
        std::string hashValue;
        TicketHashType hashType;
    };

    struct ValidateContext {
        std::string inFile;
        SignatureInfo signInfo;
        std::string developerId;
        std::string bundleName;
        std::string packageHash;
        TicketHashType packageHashType = TICKET_HASH_SHA256;
        std::vector<FileHashEntry> fileHashes;
        ProfileInfo profileInfo;
    };

    static bool ExtractValidateInfo(ValidateContext& ctx);
    static bool RunValidateChecks(ValidateContext& ctx);
    static bool ExtractTicketP7b(const SignatureInfo& signInfo, std::string& ticketP7b);
    static bool ParseTicketJson(const std::string& ticketJson, ValidateContext& ctx);
    static void ParseFileHashes(cJSON* root, std::vector<FileHashEntry>& fileHashes);
    static bool GetProfileFromBlocks(const std::vector<OptionalBlock>& optionBlocks,
        std::string& profileContent);
    static bool ComputeEntryHash(unzFile zFile, const std::string& filePath,
        TicketHashType hashType, std::string& hashHex);
    static bool VerifySubPackageHashes(const std::string& appFile,
        const std::vector<FileHashEntry>& fileHashes);
    static bool VerifyTicketPkcs7(const std::string& ticketP7b, std::string& ticketJson);
    static bool VerifyPackageHash(const std::string& packageHash, TicketHashType hashType,
        const SignatureInfo& signInfo);
    static bool VerifyProfileAssociation(const ProfileInfo& profileInfo, const std::string& devId,
        const std::string& bundleName);
    static TicketHashType ParseHashTypeFromField(const std::string& fieldName);
    static std::string FindHashField(void* obj, TicketHashType& outType);
    static const EVP_MD* GetHashMd(TicketHashType hashType);
    static std::string ComputeHashHex(const char* data, int len, TicketHashType hashType);
    static std::string ComputeHashHexStream(unzFile zFile, TicketHashType hashType);
};

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_TICKET_VALIDATE_H
