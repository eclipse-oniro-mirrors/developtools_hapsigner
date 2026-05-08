/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "verify_elf.h"

#include <fstream>
#include "cJSON.h"
#include "constant.h"
#include "signature_tools_log.h"
#include "verify_hap_openssl_utils.h"

namespace OHOS {
namespace SignatureTools {
const int FLAG_SELF_SIGN = 1 << 4;

bool VerifyElf::Verify(Options* options)
{
    // check param
    if (options == nullptr) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Param options is null.");
        return false;
    }
    std::string elfFile = options->GetString(Options::IN_FILE);
    ELFIO::elfio elfReader;
    if (!elfReader.load(elfFile)) {
        SIGNATURE_TOOLS_LOGE("failed to load input ELF file");
        return false;
    }
    PrintPermissionContent(elfReader);
    // get codesignSec section
    bool signFlag = ParseSignBlock(elfReader);
    if (!signFlag) {
        return false;
    }
    return true;
}

void VerifyElf::PrintPermissionContent(const ELFIO::elfio& elfReader)
{
    ELFIO::section* sec = elfReader.sections[PERMISSION_SEC_NAME];
    if (!sec) {
        PrintMsg("permission is not found");
        return;
    }
    const char* data = sec->get_data();
    if (sec->get_size() == 0 || data == nullptr) {
        PrintMsg("permission is empty");
        return;
    }
    std::string content(data);
    cJSON* root = cJSON_Parse(data);
    if (root) {
        char* jsonFormat = cJSON_Print(root);
        if (jsonFormat) {
            content = jsonFormat;
            free(jsonFormat);
            goto out;
        }
        free(jsonFormat);
    }
out:
    cJSON_Delete(root);
    PrintMsg("+++++++++++++++++++++++++++++++++permission+++++++++++++++++++++++++++++++++++++\n" + content);
}

bool VerifyElf::ParseSignBlock(const ELFIO::elfio& elfReader)
{
    ELFIO::section* sec = elfReader.sections[CODE_SIGN_SEC_NAME];
    if (!sec) {
        PrintMsg("code signature is not found");
        return true;
    }
    ELFIO::Elf64_Off secOffElf64 = sec->get_offset();
    uint64_t secOff = static_cast<uint64_t>(secOffElf64);
    if (secOff % PAGE_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("code signature section offset is not aligned");
        return false;
    }
    const char* data = sec->get_data();
    uint64_t csBlockSize = sec->get_size();
    if (csBlockSize == 0 || csBlockSize % PAGE_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("code signature section size is not aligned");
        return false;
    }
    if (csBlockSize < sizeof(ElfSignInfo)) {
        SIGNATURE_TOOLS_LOGE("csBlockSize is too small: %lu", csBlockSize);
        return false;
    }
    const ElfSignInfo* signInfo = reinterpret_cast<const ElfSignInfo*>(data);
    if (signInfo->signSize == 0 || (signInfo->signSize > csBlockSize - sizeof(ElfSignInfo))) {
        SIGNATURE_TOOLS_LOGE("invalid signSize: %u", signInfo->signSize);
        return false;
    }
    if ((signInfo->flags & FLAG_SELF_SIGN) == FLAG_SELF_SIGN) {
        PrintMsg("code signature is self-sign");
        return true;
    }
    Pkcs7Context pkcs7Context;
    auto signData = reinterpret_cast<const unsigned char*>(signInfo->signature);

    PKCS7* p7 = d2i_PKCS7(nullptr, &signData, signInfo->signSize);
    if (p7 == nullptr || !PKCS7_type_is_signed(p7) || p7->d.sign == nullptr) {
        SIGNATURE_TOOLS_LOGE("sign data to pcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::GetCertChains(p7, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("GetCertChains form pkcs7 failed");
        return false;
    }
    if (!PrintCertChainToCmd(pkcs7Context.certChain[0])) {
        SIGNATURE_TOOLS_LOGE("print cert chain to cmd failed");
        return false;
    }
    return true;
}

bool VerifyElf::PrintCertChainToCmd(std::vector<X509*>& certChain)
{
    BIO* outFd = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!outFd) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "The stdout stream may have errors");
        return false;
    }
    uint64_t format = XN_FLAG_SEP_COMMA_PLUS; // Print according to RFC2253
    uint64_t content = X509_FLAG_NO_EXTENSIONS | X509_FLAG_NO_ATTRIBUTES | X509_FLAG_NO_HEADER | X509_FLAG_NO_SIGDUMP;
    int num = 0;
    for (auto& cert : certChain) {
        PrintMsg("+++++++++++++++++++++++++++++++++certificate #" + std::to_string(num) +
                 "+++++++++++++++++++++++++++++++++++++");
        if (!X509_print_ex(outFd, cert, format, content)) {
            VerifyHapOpensslUtils::GetOpensslErrorMessage();
            SIGNATURE_TOOLS_LOGE("print x509 cert to cmd failed");
            BIO_free(outFd);
            return false;
        }
        ++num;
    }
    BIO_free(outFd);
    return true;
}

} // namespace SignatureTools
} // namespace OHOS