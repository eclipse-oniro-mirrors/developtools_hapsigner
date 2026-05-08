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

#include <algorithm>

#include "fs_verity_descriptor.h"
#include "fs_verity_descriptor_with_sign.h"
#include "code_signing.h"

namespace OHOS {
namespace SignatureTools {

const FsVerityHashAlgorithm FS_SHA256(1, "SHA-256", 256 / 8);
const FsVerityHashAlgorithm FS_SHA512(2, "SHA-512", 512 / 8);
const int8_t LOG_2_OF_FSVERITY_HASH_PAGE_SIZE = 12;
const int FLAG_SELF_SIGN = 1 << 4;
const uint8_t ELF_CODE_SIGN_VERSION = 0x3;

CodeSigning::CodeSigning(SignerConfig* signConfig, bool selfSign)
{
    m_signConfig = signConfig;
    m_selfSign = selfSign;
}

CodeSigning::CodeSigning()
{
}

bool CodeSigning::GetElfCodeSignBlock(const std::string &input, uint64_t& csOffset, std::vector<int8_t>& codesignData)
{
    SIGNATURE_TOOLS_LOGI("Start to sign elf code.");
    std::ifstream inputstream(input, std::ios::binary | std::ios::ate);
    if (!inputstream.is_open()) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open file: " + input + "failed");
        return false;
    }
    int flags = 0;
    if (m_selfSign) {
        flags = flags | FLAG_SELF_SIGN;
    }
    std::streamsize fileSize = inputstream.tellg();
    inputstream.seekg(0, std::ios::beg);
    std::unique_ptr<FsVerityGenerator> fsVerityGenerator = std::make_unique<FsVerityGenerator>();
    fsVerityGenerator->SetCsOffset(csOffset);
    fsVerityGenerator->GenerateFsVerityDigest(inputstream, fileSize, flags);
    std::vector<int8_t> signature;

    if (!m_selfSign) {
        std::string ownerID;
        GetOwnerIdFromCert(ownerID);
        std::vector<int8_t> fsVerityDigest = fsVerityGenerator->GetFsVerityDigest();
        bool generateSignatureFlag = GenerateSignature(fsVerityDigest, ownerID, signature);
        if (!generateSignatureFlag) {
            SIGNATURE_TOOLS_LOGE("[SignElf] generate elf signature failed");
            return false;
        }
    } else {
        signature = fsVerityGenerator->GetDescriptorDigest();
    }

    FsVerityDescriptor::Builder fsdbuilder;
    fsdbuilder.SetFileSize(fileSize)
              .SetHashAlgorithm(FS_SHA256.GetId())
              .SetLog2BlockSize(LOG_2_OF_FSVERITY_HASH_PAGE_SIZE)
              .SetSaltSize(fsVerityGenerator->GetSaltSize())
              .SetSignSize(signature.size())
              .SetSalt(fsVerityGenerator->GetSalt())
              .SetRawRootHash(fsVerityGenerator->GetRootHash())
              .SetFlags(flags)
              .SetCsVersion(ELF_CODE_SIGN_VERSION);

    FsVerityDescriptorWithSign fsVerityDescriptorWithSign =
        FsVerityDescriptorWithSign(FsVerityDescriptor(fsdbuilder), signature);
    std::vector<int8_t> treeBytes = fsVerityGenerator->GetTreeBytes();
    fsVerityDescriptorWithSign.ToByteArray(codesignData);
    return true;
}

bool CodeSigning::GenerateSignature(const std::vector<int8_t>& signedData, const std::string& ownerID,
                                    std::vector<int8_t>& ret)
{
    if (m_signConfig->GetSigner() != nullptr) {
        STACK_OF(X509)* certs = NULL;
        certs = m_signConfig->GetSigner()->GetCertificates();
        if (certs == nullptr) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "No certificates configured for sign.");
            return false;
        }
        sk_X509_pop_free(certs, X509_free);
    } else {
        return false;
    }
    std::unique_ptr<BCSignedDataGenerator> bcSignedDataGenerator =
        std::make_unique<BCSignedDataGenerator>();
    if (!ownerID.empty()) {
        SIGNATURE_TOOLS_LOGW("generate signature get owner id not null.");
        bcSignedDataGenerator->SetOwnerId(ownerID);
    }
    std::string signed_data(signedData.begin(), signedData.end());
    std::string ret_str;
    if (signedData.empty()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Generate verity digest is null");
        return false;
    }
    bool generateSignedDataFlag = bcSignedDataGenerator->GenerateSignedData(signed_data, m_signConfig, ret_str);
    if (generateSignedDataFlag) {
        SIGNATURE_TOOLS_LOGE("Generate signedData failed");
        return false;
    }
    ret = std::vector<int8_t>(ret_str.begin(), ret_str.end());
    return true;
}

bool CodeSigning::GetOwnerIdFromCert(std::string& ownerID)
{
    if (m_signConfig == nullptr || m_signConfig->GetSigner() == nullptr) {
        ownerID = "";
        return true;
    }
    STACK_OF(X509)* certs = m_signConfig->GetSigner()->GetCertificates();
    if (sk_X509_num(certs) < MIN_CERT_CHAIN_SIZE) {
        SIGNATURE_TOOLS_LOGE("sign certs not a cert chain");
        sk_X509_pop_free(certs, X509_free);
        return false;
    }
    X509* cert = sk_X509_value(certs, 0);
    X509_NAME* subject = X509_get_subject_name(cert);
    VerifyCertOpensslUtils::GetTextFromX509Name(subject, NID_organizationalUnitName, ownerID);
    sk_X509_pop_free(certs, X509_free);
    SIGNATURE_TOOLS_LOGI("organizationalUnitName = %s.", ownerID.c_str());
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
