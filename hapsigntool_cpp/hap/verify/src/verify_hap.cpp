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
#include <climits>
#include <cstdlib>
#include <regex>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <numeric>

#include "securec.h"
#include "hap_signer_block_utils.h"
#include "signature_info.h"
#include "options.h"
#include "openssl/pem.h"
#include "pkcs7_data.h"
#include "hap_utils.h"
#include "string_utils.h"
#include "verify_code_signature.h"
#include "param_constants.h"
#include "file_utils.h"
#include "cJSON.h"
#include "digest_common.h"
#include "verify_hap.h"
#include "verify_hap_openssl_utils.h"
#include "pkcs7_context.h"
#include "profile_verify.h"
#include "signature_algorithm_helper.h"

namespace OHOS {
namespace SignatureTools {

const int32_t VerifyHap::HEX_PRINT_LENGTH = 3;
const int32_t VerifyHap::DIGEST_BLOCK_LEN_OFFSET = 8;
const int32_t VerifyHap::DIGEST_ALGORITHM_OFFSET = 12;
const int32_t VerifyHap::DIGEST_LEN_OFFSET = 16;
const int32_t VerifyHap::DIGEST_OFFSET_IN_CONTENT = 20;
const std::string VerifyHap::HAP_APP_PATTERN = "[^]*.hap$";
const std::string VerifyHap::HQF_APP_PATTERN = "[^]*.hqf$";
const std::string VerifyHap::HSP_APP_PATTERN = "[^]*.hsp$";
const std::string VerifyHap::APP_APP_PATTERN = "[^]*.app$";
static constexpr int ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH = 12;

VerifyHap::VerifyHap() : isPrintCert(true)
{
}

VerifyHap::VerifyHap(bool printCert)
{
    isPrintCert = printCert;
}

void VerifyHap::setIsPrintCert(bool printCert)
{
    isPrintCert = printCert;
}

bool VerifyHap::HapOutPutPkcs7(PKCS7* p7, const std::string& outPutPath)
{
    std::string p7bContent = StringUtils::Pkcs7ToString(p7);
    if (p7bContent.empty()) {
        SIGNATURE_TOOLS_LOGE("p7b to string failed!\n");
        return false;
    }
    if (FileUtils::Write(p7bContent, outPutPath) < 0) {
        SIGNATURE_TOOLS_LOGE("p7b write to file falied!\n");
        return false;
    }
    return true;
}

bool VerifyHap::outputOptionalBlocks(const std::string& outputProfileFile, const std::string& outputProofFile,
                                     const std::string& outputPropertyFile,
                                     const std::vector<OptionalBlock>& optionBlocks)
{
    for (auto& optionBlock : optionBlocks) {
        if (optionBlock.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, outputProfileFile)) {
                return false;
            }
        } else if (optionBlock.optionalType == HapUtils::HAP_PROPERTY_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, outputPropertyFile)) {
                return false;
            }
        } else if (optionBlock.optionalType == HapUtils::HAP_PROOF_OF_ROTATION_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, outputProofFile)) {
                return false;
            }
        } else {
            SIGNATURE_TOOLS_LOGE("Unsupported Block Id: %d", optionBlock.optionalType);
            return false;
        }
    }
    return true;
}

bool VerifyHap::outputReSignOptionalBlocks(const std::string& outputHapSignFile,
                                           const std::string& outputCodeResignFile,
                                           const std::vector<OptionalBlock>& optionBlocks)
{
    for (auto& optionBlock : optionBlocks) {
        if (optionBlock.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, ParamConstants::PARAM_VERIFY_PROFILE_FILE)) {
                return false;
            }
        } else if (optionBlock.optionalType == HapUtils::HAP_PROPERTY_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, ParamConstants::PARAM_VERIFY_PROPERTY_FILE)) {
                return false;
            }
        } else if (optionBlock.optionalType == HapUtils::HAP_PROOF_OF_ROTATION_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, ParamConstants::PARAM_VERIFY_PROOF_FILE)) {
                return false;
            }
        } else if (optionBlock.optionalType == HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, outputHapSignFile)) {
                return false;
            }
        } else if (optionBlock.optionalType == HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID) {
            if (!writeOptionalBytesToFile(optionBlock, outputCodeResignFile)) {
                return false;
            }
        } else {
            SIGNATURE_TOOLS_LOGE("Unsupported Block Id: %d", optionBlock.optionalType);
            return false;
        }
    }
    return true;
}

bool VerifyHap::writeOptionalBytesToFile(const OptionalBlock& optionalBlock, const std::string& path)
{
    if (path.empty()) {
        return true;
    }
    std::string optionBlockString(optionalBlock.optionalBlockValue.GetBufferPtr(),
                          optionalBlock.optionalBlockValue.GetCapacity());
    if (FileUtils::Write(optionBlockString, path) < 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "write optional bytes to file:" + path + " falied!");
        return false;
    }
    return true;
}

bool VerifyHap::HapOutPutCertChain(std::vector<X509*>& certs, const std::string& outPutPath)
{
    if (isPrintCert) {
        if (!PrintCertChainToCmd(certs)) {
            SIGNATURE_TOOLS_LOGE("print cert chain to cmd failed\n");
            return false;
        }
    }
    VerifyHapOpensslUtils::GetOpensslErrorMessage();
    SIGNATURE_TOOLS_LOGD("outPutPath = %s", outPutPath.c_str());
    std::vector<std::string> certStr;
    for (auto& cert : certs) {
        certStr.emplace_back(StringUtils::SubjectToString(cert));
        certStr.emplace_back(StringUtils::x509CertToString(cert));
    }
    std::string outPutCertChainContent = std::accumulate(certStr.begin(), certStr.end(), std::string(),
        [](std::string sum, const std::string& certstr) { return sum + certstr; });
    if (FileUtils::Write(outPutCertChainContent, outPutPath) < 0) {
        SIGNATURE_TOOLS_LOGE("certChain write to file falied!\n");
        return false;
    }
    return true;
}

bool VerifyHap::PrintCertChainToCmd(std::vector<X509*>& certChain)
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

int32_t VerifyHap::Verify(const std::string& filePath, Options* options)
{
    SIGNATURE_TOOLS_LOGD("Start Verify");
    std::string standardFilePath;
    if (!CheckFilePath(filePath, standardFilePath)) {
        SIGNATURE_TOOLS_LOGE("Check file path%s failed", filePath.c_str());
        return IO_ERROR;
    }
    RandomAccessFile hapFile;
    if (!hapFile.Init(standardFilePath)) {
        SIGNATURE_TOOLS_LOGE("%s init failed", standardFilePath.c_str());
        return ZIP_ERROR;
    }
    int32_t resultCode = Verify(hapFile, options, filePath);
    if (resultCode != RET_OK) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, standardFilePath + " verify failed");
    }
    return resultCode;
}

int32_t VerifyHap::VerifyBeforeResign(const std::string& filePath, Options* options)
{
    SIGNATURE_TOOLS_LOGD("Start Verify");
    std::string standardFilePath;
    if (!CheckFilePath(filePath, standardFilePath)) {
        SIGNATURE_TOOLS_LOGE("Check file path%s failed", filePath.c_str());
        return IO_ERROR;
    }
    RandomAccessFile hapFile;
    if (!hapFile.Init(standardFilePath)) {
        SIGNATURE_TOOLS_LOGE("%s init failed", standardFilePath.c_str());
        return ZIP_ERROR;
    }
    int32_t resultCode = VerifyBeforeResign(hapFile, options, filePath);
    if (resultCode != RET_OK) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, standardFilePath + " verify failed");
    }
    return resultCode;
}

bool VerifyHap::CheckFilePath(const std::string& filePath, std::string& standardFilePath)
{
    char path[PATH_MAX] = { 0x00 };
    if (filePath.size() > PATH_MAX || realpath(filePath.c_str(), path) == nullptr) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
                            filePath + " does not exist or is over " + std::to_string(PATH_MAX) + " chars");
        return false;
    }
    standardFilePath = std::string(path);
    std::string standardFilePathTmp = std::string(path);
    std::transform(standardFilePathTmp.begin(), standardFilePathTmp.end(), standardFilePathTmp.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    bool ret = (!std::regex_match(standardFilePathTmp, std::regex(HAP_APP_PATTERN)) &&
                !std::regex_match(standardFilePathTmp, std::regex(HSP_APP_PATTERN)) &&
                !std::regex_match(standardFilePathTmp, std::regex(APP_APP_PATTERN)) &&
                !std::regex_match(standardFilePathTmp, std::regex(HQF_APP_PATTERN)));
    if (ret) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "only support format is [hap, hqf, hsp, app]");
        return false;
    }
    return true;
}

bool VerifyHap::IsVerifyResign(const SignatureInfo& hapSignInfo)
{
    for (const OptionalBlock& optionalBlock : hapSignInfo.optionBlocks) {
        if (optionalBlock.optionalType == HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID) {
            return true;
        }
    }
    return false;
}

bool VerifyHap::IsEnterpriseProfileDistributionType(const SignatureInfo& hapSignInfo)
{
    const ByteBuffer* profileBlock = nullptr;
    for (const auto& block : hapSignInfo.optionBlocks) {
        if (block.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            profileBlock = &block.optionalBlockValue;
            break;
        }
    }
    if (!profileBlock) {
        SIGNATURE_TOOLS_LOGE("[VerifyEnterpriseProfileType] No profile block found");
        return false;
    }

    std::string profileContent(profileBlock->GetBufferPtr(), profileBlock->GetCapacity());
    std::string profileContentclean;
    GetProfileContent(profileContent, profileContentclean);

    ProfileInfo info;
    if (!ParseProfile(profileContentclean, info)) {
        SIGNATURE_TOOLS_LOGE("[VerifyEnterpriseProfileType] Failed to parse profile");
        return false;
    }

    bool isValidEnterpriseType = (info.distributionType == AppDistType::ENTERPRISE_NORMAL ||
                                  info.distributionType == AppDistType::ENTERPRISE_MDM ||
                                  info.distributionType == AppDistType::ENTERPRISE);

    if (!isValidEnterpriseType) {
        SIGNATURE_TOOLS_LOGE("[VerifyEnterpriseProfileType] Invalid enterprise distribution type");
        return false;
    }

    return true;
}

X509* VerifyHap::ExtractCertificateFromProfile(const SignatureInfo& hapSignInfo)
{
    const ByteBuffer* profileBlock = nullptr;
    for (const auto& block : hapSignInfo.optionBlocks) {
        if (block.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            profileBlock = &block.optionalBlockValue;
            break;
        }
    }
    if (!profileBlock) {
        return nullptr;
    }

    std::string profileContent(profileBlock->GetBufferPtr(), profileBlock->GetCapacity());
    std::string cleanContent;

    int32_t result = GetProfileContent(profileContent, cleanContent);
    if (result != 0) {
        return nullptr;
    }

    ProfileInfo info;
    if (!ParseProfile(cleanContent, info)) {
        return nullptr;
    }

    if (info.type == ProvisionType::RELEASE) {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_write(bio, info.bundleInfo.distributionCertificate.c_str(),
                  static_cast<int>(info.bundleInfo.distributionCertificate.length()));
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        return cert;
    } else if (info.type == ProvisionType::DEBUG) {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_write(bio, info.bundleInfo.developmentCertificate.c_str(),
                  static_cast<int>(info.bundleInfo.developmentCertificate.length()));
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        return cert;
    }

    return nullptr;
}

bool VerifyHap::CheckInputCertMatchWithCertchain(X509* inputCert, const SignatureInfo& hapSignInfo)
{
    const ByteBuffer* signatureBlock = nullptr;
    for (const auto& block : hapSignInfo.optionBlocks) {
        if (block.optionalType == HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID) {
            signatureBlock = &block.optionalBlockValue;
            break;
        }
    }
    if (!signatureBlock) {
        SIGNATURE_TOOLS_LOGE("Get signatureBlock failed");
        return false;
    }

    if (signatureBlock->GetCapacity() == 0) {
        return false;
    }

    Pkcs7Context pkcs7Context;
    if (!VerifyAppPkcs7(pkcs7Context, *signatureBlock)) {
        return false;
    }

    if (CheckInputCertMatchWithProfile(inputCert, pkcs7Context.certChain[0][0])) {
        return true;
    }

    return false;
}

bool VerifyHap::VerifyCertificateConsistency(const SignatureInfo& hapSignInfo)
{
    X509* profileCert = ExtractCertificateFromProfile(hapSignInfo);
    bool result = CheckInputCertMatchWithCertchain(profileCert, hapSignInfo);
    X509_free(profileCert);
    return result;
}

bool VerifyHap::CheckInputCertMatchWithProfile(X509* inputCert, X509* certInProfile)
{
    bool ret = true;
    if (inputCert == nullptr || certInProfile == nullptr) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "The certificate is empty");
        return false;
    }
    X509_NAME* subject1 = X509_get_subject_name(inputCert);
    X509_NAME* subject2 = X509_get_subject_name(certInProfile);
    if (X509_NAME_cmp(subject1, subject2) != 0) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "The subject does not match!");
        return false;
    }
    X509_NAME* issuer1 = X509_get_issuer_name(inputCert);
    X509_NAME* issuer2 = X509_get_issuer_name(certInProfile);
    if (X509_NAME_cmp(issuer1, issuer2) != 0) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "The issuer name does not match!");
        return false;
    }
    ASN1_INTEGER* serial1 = X509_get_serialNumber(inputCert);
    ASN1_INTEGER* serial2 = X509_get_serialNumber(certInProfile);
    if (ASN1_INTEGER_cmp(serial1, serial2) != 0) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "serial number does not match!");
        return false;
    }
    EVP_PKEY* pkey1 = X509_get_pubkey(inputCert);
    EVP_PKEY* pkey2 = X509_get_pubkey(certInProfile);
    if (pkey1 != nullptr && pkey2 != nullptr && EVP_PKEY_cmp(pkey1, pkey2) != 1) {
        EVP_PKEY_free(pkey1);
        EVP_PKEY_free(pkey2);
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "The public key does not match!");
        return false;
    }
    if (pkey1 == nullptr || pkey2 == nullptr) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "The public key is null!");
        ret = false;
    }
    if (pkey1 != nullptr) {
        EVP_PKEY_free(pkey1);
    }
    if (pkey2 != nullptr) {
        EVP_PKEY_free(pkey2);
    }
    return ret;
}

bool VerifyHap::VerifyCRL(Pkcs7Context& pkcs7Context)
{
    STACK_OF(X509_CRL)* x509Crl = pkcs7Context.p7->d.sign->crl;

    if (!VerifyCertOpensslUtils::VerifyCrl(pkcs7Context.certChain[0], x509Crl, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify Crl stack failed");
        return false;
    }
    return true;
}

int32_t VerifyHap::VerifyResign(RandomAccessFile& hapFile, SignatureInfo& hapSignInfo,
                                Options* options, const std::string& filePath)
{
    if (VerifyOriginalPackageSignature(hapFile, hapSignInfo, options) != RET_OK) {
        SIGNATURE_TOOLS_LOGE("Verify Original Package Signature failed");
        return VERIFY_ERROR;
    }

    if (!VerifyCertificateConsistency(hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Certificate Consistency failed");
        return VERIFY_ERROR;
    }

    if (!IsEnterpriseProfileDistributionType(hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Enterprise Profile failed");
        return VERIFY_ERROR;
    }

    if (CheckCodeSign(filePath, hapSignInfo.optionBlocks, hapSignInfo.hapSignatureBlock) == false) {
        SIGNATURE_TOOLS_LOGE("check code sign failed\n");
        return VERIFY_ERROR;
    }

    Pkcs7Context pkcs7Context;
    if (!VerifyAppPkcs7(pkcs7Context, hapSignInfo.hapSignatureBlock)) {
        return PARSE_ERROR;
    }

    if (!GetDigestAndAlgorithm(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Get digest failed");
        return PARSE_ERROR;
    }

    if (!VerifyCRL(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify CRL failed");
        return VERIFY_ERROR;
    }

    if (!HapSignerBlockUtils::VerifyHapIntegrity(pkcs7Context, hapFile, hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Integrity failed");
        return VERIFY_ERROR;
    }
    if (!HapOutPutCertChain(pkcs7Context.certChain[0],
        options->GetString(Options::OUT_CERT_CHAIN))) {
        SIGNATURE_TOOLS_LOGE("out put cert chain failed");
        return IO_ERROR;
    }

    if (!outputReSignOptionalBlocks(options->GetString(ParamConstants::PARAM_VERIFY_HAP_SIGN_FILE),
                                    options->GetString(ParamConstants::PARAM_VERIFY_CODE_RESIGN_FILE),
                                    hapSignInfo.optionBlocks)) {
        SIGNATURE_TOOLS_LOGE("output Optional Blocks failed");
        return IO_ERROR;
    }
    return RET_OK;
}

int32_t VerifyHap::VerifyOriginalPackageSignature(RandomAccessFile& hapFile, SignatureInfo& hapSignInfo,
                                                  Options* options)
{
    const ByteBuffer* profileBlock = nullptr;
    for (const auto& block : hapSignInfo.optionBlocks) {
        if (block.optionalType == HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID) {
            profileBlock = &block.optionalBlockValue;
            break;
        }
    }
    if (!profileBlock) {
        SIGNATURE_TOOLS_LOGE("Get profileBlock failed");
        return PARSE_ERROR;
    }

    Pkcs7Context pkcs7Context;
    if (!VerifyAppPkcs7(pkcs7Context, *profileBlock)) {
        return PARSE_ERROR;
    }

    if (!GetDigestAndAlgorithm(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Get digest failed");
        return PARSE_ERROR;
    }

    if (!VerifyCRL(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify CRL failed");
        return VERIFY_ERROR;
    }

    if (!HapSignerBlockUtils::VerifyOldHapIntegrity(pkcs7Context, hapFile, hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Integrity failed");
        return VERIFY_ERROR;
    }
    
    if (!HapOutPutCertChain(pkcs7Context.certChain[0],
        options->GetString(Options::OUT_CERT_CHAIN))) {
        SIGNATURE_TOOLS_LOGE("out put cert chain failed");
        return IO_ERROR;
    }
    return RET_OK;
}

int32_t VerifyHap::Verify(RandomAccessFile& hapFile, Options* options, const std::string& filePath)
{
    SignatureInfo hapSignInfo;
    if (!HapSignerBlockUtils::FindHapSignature(hapFile, hapSignInfo)) {
        return ZIP_ERROR;
    }

    if (IsVerifyResign(hapSignInfo)) {
        return VerifyResign(hapFile, hapSignInfo, options, filePath);
    }
    if (CheckCodeSign(filePath, hapSignInfo.optionBlocks, hapSignInfo.hapSignatureBlock) == false) {
        SIGNATURE_TOOLS_LOGE("check code sign failed\n");
        return VERIFY_ERROR;
    }

    Pkcs7Context pkcs7Context;
    if (!VerifyAppPkcs7(pkcs7Context, hapSignInfo.hapSignatureBlock)) {
        return PARSE_ERROR;
    }

    if (!GetDigestAndAlgorithm(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Get digest failed");
        return PARSE_ERROR;
    }

    if (!VerifyCRL(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify CRL failed");
        return VERIFY_ERROR;
    }

    if (!HapSignerBlockUtils::VerifyHapIntegrity(pkcs7Context, hapFile, hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Integrity failed");
        return VERIFY_ERROR;
    }
    if (!HapOutPutCertChain(pkcs7Context.certChain[0],
        options->GetString(Options::OUT_CERT_CHAIN))) {
        SIGNATURE_TOOLS_LOGE("out put cert chain failed");
        return IO_ERROR;
    }

    if (!outputOptionalBlocks(options->GetString(ParamConstants::PARAM_VERIFY_PROFILE_FILE),
                              options->GetString(ParamConstants::PARAM_VERIFY_PROOF_FILE),
                              options->GetString(ParamConstants::PARAM_VERIFY_PROPERTY_FILE),
                              hapSignInfo.optionBlocks)) {
        SIGNATURE_TOOLS_LOGE("output Optional Blocks failed");
        return IO_ERROR;
    }
    return RET_OK;
}

int32_t VerifyHap::VerifyBeforeResign(RandomAccessFile& hapFile, Options* options, const std::string& filePath)
{
    SignatureInfo hapSignInfo;
    if (!HapSignerBlockUtils::FindHapSignature(hapFile, hapSignInfo)) {
        return ZIP_ERROR;
    }

    if (CheckCodeSign(filePath, hapSignInfo.optionBlocks, hapSignInfo.hapSignatureBlock) == false) {
        SIGNATURE_TOOLS_LOGE("check code sign failed\n");
        return VERIFY_ERROR;
    }

    Pkcs7Context pkcs7Context;
    if (!VerifyAppPkcs7(pkcs7Context, hapSignInfo.hapSignatureBlock)) {
        return PARSE_ERROR;
    }

    if (!GetDigestAndAlgorithm(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Get digest failed");
        return PARSE_ERROR;
    }

    if (!VerifyCRL(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify CRL failed");
        return VERIFY_ERROR;
    }

    if (!HapSignerBlockUtils::VerifyHapIntegrity(pkcs7Context, hapFile, hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Integrity failed");
        return VERIFY_ERROR;
    }
    return RET_OK;
}

bool VerifyHap::CheckFileNameAndBlockArray(const std::string& hapFilePath,
                                           const ByteBuffer& propertyBlockArray)const
{
    std::vector<std::string> fileNameArray = StringUtils::SplitString(hapFilePath, '.');
    if (fileNameArray.size() < ParamConstants::FILE_NAME_MIN_LENGTH) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "ZIP64 format not supported.");
        return false;
    }

    if (propertyBlockArray.GetCapacity() < ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH) {
        return false;
    }
    return true;
}

bool VerifyHap::CheckCodeSign(const std::string& hapFilePath,
                              const std::vector<OptionalBlock>& optionalBlocks,
                              const ByteBuffer& hapSignatureBlock)const
{
    bool codeReSignFlag;
    bool codeSignFlag;
    ByteBuffer propertyBlockArray;
    if (!BuildBlockInfo(hapFilePath, optionalBlocks, codeReSignFlag, codeSignFlag, propertyBlockArray)) {
        return false;
    }
    if (!codeReSignFlag && !codeSignFlag) {
        SIGNATURE_TOOLS_LOGI("can not find codesign block.");
        return true;
    }
    propertyBlockArray.SetPosition(0);
    if (!CheckFileNameAndBlockArray(hapFilePath, propertyBlockArray)) {
        return false;
    }

    std::unordered_map<int, ByteBuffer> blockMap;
    for (const OptionalBlock& block : optionalBlocks) {
        blockMap.emplace(block.optionalType, block.optionalBlockValue);
    }
    ByteBuffer codeSignBlock;
    std::string profileContent;
    if (!ExtractCodeSignBlock(hapFilePath, propertyBlockArray, blockMap, profileContent, codeSignBlock)) {
        return false;
    }

    Pkcs7Context profilePkcs7Context;
    if (!VerifyCodeAndProfile(hapFilePath, profileContent, codeSignBlock, hapSignatureBlock, profilePkcs7Context)) {
        return false;
    }

    if (!CheckPermSign(hapFilePath, propertyBlockArray, profileContent, codeSignBlock, profilePkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("verify perm sign failed, file: %s", hapFilePath.c_str());
        return false;
    }
    SIGNATURE_TOOLS_LOGI("verify perm sign success.");
    return true;
}

bool VerifyHap::BuildBlockInfo(const std::string& hapFilePath, const std::vector<OptionalBlock>& optionalBlocks,
                               bool& codeReSignFlag, bool& codeSignFlag, ByteBuffer& propertyBlockArray) const
{
    std::unordered_map<int, ByteBuffer> blockMap;
    for (const OptionalBlock& block : optionalBlocks) {
        blockMap.emplace(block.optionalType, block.optionalBlockValue);
    }
    codeReSignFlag = blockMap.find(HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID) != blockMap.end() &&
        blockMap[HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID].GetCapacity() > 0;
    codeSignFlag = blockMap.find(HapUtils::HAP_PROPERTY_BLOCK_ID) != blockMap.end() &&
        blockMap[HapUtils::HAP_PROPERTY_BLOCK_ID].GetCapacity() > 0;
    if (!codeReSignFlag && !codeSignFlag) {
        return true;
    }
    propertyBlockArray = blockMap[HapUtils::HAP_PROPERTY_BLOCK_ID];
    if (codeReSignFlag) {
        propertyBlockArray = blockMap[HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID];
    }
    return true;
}

bool VerifyHap::ExtractCodeSignBlock(const std::string& hapFilePath, ByteBuffer& propertyBlockArray,
                                     std::unordered_map<int, ByteBuffer>& blockMap,
                                     std::string& profileContent, ByteBuffer& codeSignBlock) const
{
    std::vector<std::string> fileNameArray = StringUtils::SplitString(hapFilePath, '.');
    uint32_t blockType;
    propertyBlockArray.GetUInt32(OFFSET_ZERO, blockType);
    uint32_t blockLength;
    propertyBlockArray.GetUInt32(OFFSET_FOUR, blockLength);
    uint32_t blockOffset;
    propertyBlockArray.GetUInt32(OFFSET_EIGHT, blockOffset);

    if (blockType != HapUtils::HAP_CODE_SIGN_BLOCK_ID) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "code sign data not exist in hap " + hapFilePath);
        return false;
    }
    codeSignBlock.SetCapacity(blockLength);
    codeSignBlock.PutData(propertyBlockArray.GetBufferPtr() + ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH, blockLength);

    auto ite = blockMap.find(HapUtils::HAP_PROFILE_BLOCK_ID);
    if (ite == blockMap.end()) {
        return false;
    }
    ByteBuffer profileArray = ite->second;
    std::string profileArray_(profileArray.GetBufferPtr(), profileArray.GetCapacity());
    if (GetProfileContent(profileArray_, profileContent) < 0) {
        SIGNATURE_TOOLS_LOGE("get profile content failed, file: %s", hapFilePath.c_str());
        return false;
    }
    std::string suffix = fileNameArray[fileNameArray.size() - 1];
    if (!VerifyCodeSignature::VerifyHap(hapFilePath, blockOffset, blockLength, suffix, profileContent)) {
        SIGNATURE_TOOLS_LOGE("verify codesign failed, file: %s", hapFilePath.c_str());
        return false;
    }
    SIGNATURE_TOOLS_LOGI("verify codesign success.");
    return true;
}

bool VerifyHap::VerifyCodeAndProfile(const std::string& hapFilePath, const std::string& profileContent,
                                     const ByteBuffer& codeSignBlock, const ByteBuffer& hapSignatureBlock,
                                     Pkcs7Context& profilePkcs7Context) const
{
    const unsigned char* profilePkcs7Data = reinterpret_cast<const unsigned char*>(hapSignatureBlock.GetBufferPtr());
    if (!VerifyHapOpensslUtils::ParsePkcs7Package(profilePkcs7Data,
        static_cast<uint32_t>(hapSignatureBlock.GetCapacity()), profilePkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("parse profile PKCS7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::GetCertChains(profilePkcs7Context.p7, profilePkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("get profile cert chains failed");
        return false;
    }
    return true;
}

bool VerifyHap::ComputeDigest(const std::string& content, std::vector<int8_t>& digest, int32_t signAlgId)
{
    if (content.empty()) {
        return false;
    }

    const EVP_MD* hash = (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) ? EVP_sha256() : EVP_sha384();
    int32_t digestLen = (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) ? SHA256_DIGEST_LENGTH : SHA384_DIGEST_LENGTH;
    unsigned char hashResult[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_Digest(content.c_str(), content.size(), hashResult, &hashLen, hash, nullptr) != 1) {
        return false;
    }

    digest.resize(digestLen);
    for (int i = 0; i < digestLen; i++) {
        digest[i] = (int8_t)hashResult[i];
    }
    return true;
}

bool VerifyHap::CheckPermSign(const std::string& hapFilePath, ByteBuffer& propertyBlockArray,
                               const std::string& profileContent, const ByteBuffer& codeSignBlock,
                               Pkcs7Context& profilePkcs7Context)const
{
    int32_t pos = ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH + codeSignBlock.GetCapacity();
    if (pos >= propertyBlockArray.GetCapacity()) {
        SIGNATURE_TOOLS_LOGI("no more blocks after code sign block.");
        return true;
    }
    while (pos < propertyBlockArray.GetCapacity()) {
        uint32_t blockType;
        uint32_t blockLength;
        uint32_t blockOffset;
        if (!propertyBlockArray.GetUInt32(pos, blockType) ||
            !propertyBlockArray.GetUInt32(pos + OFFSET_FOUR, blockLength) ||
            !propertyBlockArray.GetUInt32(pos + OFFSET_EIGHT, blockOffset)) {
            SIGNATURE_TOOLS_LOGE("read block header failed at pos %d", pos);
            return false;
        }

        if (blockLength > propertyBlockArray.GetCapacity()) {
            SIGNATURE_TOOLS_LOGE("invalid block length %u at pos %d, skip", blockLength, pos);
            pos += ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH;
            continue;
        }

        if (blockType == HapUtils::PERMISSION_SIGN_BLOCK_ID) {
            int32_t dataStartPos = pos;
            const char* srcBuf = propertyBlockArray.GetBufferPtr();
            if (srcBuf == nullptr || dataStartPos + blockLength > propertyBlockArray.GetCapacity()) {
                SIGNATURE_TOOLS_LOGE("perm sign data out of range: start=%d, len=%u, capacity=%d",
                    dataStartPos, blockLength, propertyBlockArray.GetCapacity());
                return false;
            }
            ByteBuffer permSignBlock;
            permSignBlock.SetCapacity(blockLength + ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH);
            permSignBlock.PutData(propertyBlockArray.GetBufferPtr() + dataStartPos,
                blockLength + ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH);
            permSignBlock.SetPosition(0);
            return VerifyPermSignBlock(permSignBlock, profileContent, hapFilePath, codeSignBlock, profilePkcs7Context);
        }
        pos += ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH + blockLength;
    }
    SIGNATURE_TOOLS_LOGI("can not find perm sign block.");
    return true;
}

bool VerifyHap::VerifyPermSignBlock(ByteBuffer& permSignBlock, const std::string& profileContent,
                                     const std::string& hapFilePath, const ByteBuffer& codeSignBlock,
                                     Pkcs7Context& profilePkcs7Context)const
{
    if (permSignBlock.GetCapacity() < ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH) {
        SIGNATURE_TOOLS_LOGE("perm sign block size too small.");
        return false;
    }

    int32_t signAlgId;
    if (!GetSignAlgId(permSignBlock, signAlgId)) {
        return false;
    }

    const EVP_MD* hash = nullptr;
    int32_t digestSize = 0;
    if (!GetHashAlgorithm(signAlgId, hash, digestSize)) {
        return false;
    }

    int16_t num;
    permSignBlock.GetInt16(28, num);
    std::string storedDigests;
    if (!ReadStoredDigests(permSignBlock, num, digestSize, storedDigests)) {
        return false;
    }

    std::string signature;
    if (!ReadSignature(permSignBlock, num, digestSize, signature)) {
        return false;
    }

    EVP_PKEY* pubKey = GetProfilePubKey(profilePkcs7Context);
    if (pubKey == nullptr) {
        return false;
    }

    if (!VerifyPermSignSignature(signature, storedDigests, hash, pubKey)) {
        SIGNATURE_TOOLS_LOGE("verify perm sign signature failed.");
        return false;
    }

    SIGNATURE_TOOLS_LOGI("verify perm sign block success.");
    return true;
}

bool VerifyHap::GetSignAlgId(ByteBuffer& permSignBlock, int32_t& signAlgId)const
{
    std::vector<int8_t> magic = HapUtils::GetPermissionSignMagic();
    for (int i = 0; i < 8; i++) {
        int8_t val;
        permSignBlock.GetInt8(12 + i, val);
        if (val != magic[i]) {
            SIGNATURE_TOOLS_LOGE("perm sign block magic mismatch at pos %d: expected %02x, got %02x",
                12 + i, (uint8_t)magic[i], (uint8_t)val);
            return false;
        }
    }
    permSignBlock.GetInt32(20, signAlgId);
    return true;
}

bool VerifyHap::GetHashAlgorithm(int32_t signAlgId, const EVP_MD*& hash, int32_t& digestSize)const
{
    if (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) {
        hash = EVP_sha256();
        digestSize = 32;
    } else if (signAlgId == ALGORITHM_SHA384_WITH_ECDSA) {
        hash = EVP_sha384();
        digestSize = 48;
    } else {
        SIGNATURE_TOOLS_LOGE("unsupported sign algorithm id: 0x%08x", signAlgId);
        return false;
    }
    return true;
}

bool VerifyHap::ReadStoredDigests(ByteBuffer& permSignBlock, int16_t num, int32_t digestSize,
                                   std::string& storedDigests)const
{
    int32_t digestPos = 30;
    for (int i = 0; i < num; i++) {
        digestPos += 4;
        for (int j = 0; j < digestSize; j++) {
            uint8_t val;
            permSignBlock.GetUInt8(digestPos + j, val);
            storedDigests.push_back((char)val);
        }
        digestPos += digestSize;
    }
    return true;
}

bool VerifyHap::ReadSignature(ByteBuffer& permSignBlock, int16_t num, int32_t digestSize,
                               std::string& signature)const
{
    int32_t sigPos = 30 + num * (4 + digestSize);
    int32_t sigLen;
    permSignBlock.GetInt32(sigPos, sigLen);
    int32_t sigOffset = sigPos + 4;
    for (int i = 0; i < sigLen; i++) {
        uint8_t val;
        permSignBlock.GetUInt8(sigOffset + i, val);
        signature.push_back((char)val);
    }
    return true;
}

EVP_PKEY* VerifyHap::GetProfilePubKey(Pkcs7Context& profilePkcs7Context)const
{
    if (profilePkcs7Context.certChain.empty() || profilePkcs7Context.certChain[0].empty()) {
        SIGNATURE_TOOLS_LOGE("profile cert chain is empty");
        return nullptr;
    }
    X509* pubKeyCert = profilePkcs7Context.certChain[0][0];
    if (pubKeyCert == nullptr) {
        SIGNATURE_TOOLS_LOGE("profile pub key cert is null");
        return nullptr;
    }
    EVP_PKEY* pubKey = X509_get0_pubkey(pubKeyCert);
    if (pubKey == nullptr) {
        SIGNATURE_TOOLS_LOGE("get profile pub key failed");
        return nullptr;
    }
    return pubKey;
}

bool VerifyHap::GetFileContentFromHap(const std::string& hapFilePath, const std::string& fileName,
                                       std::string& content)const
{
    unzFile zFile = unzOpen(hapFilePath.c_str());
    if (zFile == NULL) {
        SIGNATURE_TOOLS_LOGE("open hap file: %s failed.", hapFilePath.c_str());
        return false;
    }

    if (unzLocateFile(zFile, fileName.c_str(), 0) != UNZ_OK) {
        SIGNATURE_TOOLS_LOGI("locate %s failed.", fileName.c_str());
        unzClose(zFile);
        return false;
    }

    unz_file_info zFileInfo;
    if (unzGetCurrentFileInfo(zFile, &zFileInfo, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK) {
        SIGNATURE_TOOLS_LOGE("get %s info failed.", fileName.c_str());
        unzClose(zFile);
        return false;
    }

    if (unzOpenCurrentFile(zFile) != UNZ_OK) {
        SIGNATURE_TOOLS_LOGE("open %s failed.", fileName.c_str());
        unzClose(zFile);
        return false;
    }

    char buffer[4096] = {0};
    int readSize = 0;
    std::stringbuf sb;
    do {
        readSize = unzReadCurrentFile(zFile, buffer, sizeof(buffer));
        if (readSize > 0) {
            sb.sputn(buffer, readSize);
        }
    } while (readSize > 0);

    content = sb.str();
    unzCloseCurrentFile(zFile);
    unzClose(zFile);
    return true;
}

bool VerifyHap::VerifyPermSignSignature(const std::string& signature, const std::string& storedDigests,
                                        const EVP_MD* hash, EVP_PKEY* pubKey)const
{
    if (signature.empty()) {
        SIGNATURE_TOOLS_LOGI("no signature data, skip signature verification.");
        return true;
    }
    if (pubKey == nullptr) {
        SIGNATURE_TOOLS_LOGE("pubKey is null");
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        SIGNATURE_TOOLS_LOGE("create EVP_MD_CTX failed");
        return false;
    }
    const unsigned char* pSigData = reinterpret_cast<const unsigned char*>(signature.data());
    bool ret = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, hash, nullptr, pubKey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, storedDigests.data(), storedDigests.size()) == 1 &&
        EVP_DigestVerifyFinal(ctx, pSigData, signature.size()) == 1) {
        ret = true;
    }
    EVP_MD_CTX_free(ctx);
    if (!ret) {
        SIGNATURE_TOOLS_LOGE("verify signature failed");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("signature verified successfully.");
    return true;
}

std::string VerifyHap::ComputeAllDigests(const std::vector<int32_t>& digestTypes,
                                          const std::string& profileContent,
                                          const std::string& hapFilePath,
                                          const ByteBuffer& codeSignBlock,
                                          int32_t signAlgId)const
{
    std::string allDigests;

    for (int32_t type : digestTypes) {
        std::vector<int8_t> digest;

        switch (type) {
            case HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION:
                if (!ComputeDigest(profileContent, digest, signAlgId)) {
                    SIGNATURE_TOOLS_LOGE("compute provision digest failed.");
                    return "";
                }
                break;

            case HapUtils::PERMISSION_SIGN_DIGEST_TYPE_MODULE_JSON: {
                std::string moduleJsonContent;
                if (!GetFileContentFromHap(hapFilePath, "module.json", moduleJsonContent)) {
                    SIGNATURE_TOOLS_LOGI("module.json not found, skip.");
                    continue;
                }
                if (!ComputeDigest(moduleJsonContent, digest, signAlgId)) {
                    SIGNATURE_TOOLS_LOGE("compute module.json digest failed.");
                    return "";
                }
                break;
            }

            case HapUtils::PERMISSION_SIGN_DIGEST_TYPE_CODE_SIGN_BLOCK: {
                std::string codeSignData(codeSignBlock.GetBufferPtr(), codeSignBlock.GetCapacity());
                if (!ComputeDigest(codeSignData, digest, signAlgId)) {
                    SIGNATURE_TOOLS_LOGE("compute code sign block digest failed.");
                    return "";
                }
                break;
            }

            case HapUtils::PERMISSION_SIGN_DIGEST_TYPE_SHARED_FILE: {
                std::string sharedFileDigest = ComputeSharedFileDigest(hapFilePath, signAlgId);
                if (sharedFileDigest.empty()) {
                    continue;
                }
                allDigests += sharedFileDigest;
                continue;
            }

            default:
                SIGNATURE_TOOLS_LOGW("unknown digest type: %d", type);
                continue;
        }

        allDigests.append(reinterpret_cast<const char*>(digest.data()), digest.size());
    }

    return allDigests;
}

std::string VerifyHap::ComputeSharedFileDigest(const std::string& hapFilePath, int32_t signAlgId)const
{
    std::string moduleJsonContent;
    if (!GetFileContentFromHap(hapFilePath, "module.json", moduleJsonContent)) {
        return "";
    }

    cJSON* root = cJSON_ParseWithOpts(moduleJsonContent.c_str(), nullptr, 1);
    if (root == nullptr) {
        return "";
    }

    cJSON* moduleObj = cJSON_GetObjectItem(root, "module");
    if (moduleObj == nullptr) {
        cJSON_Delete(root);
        return "";
    }

    cJSON* shareFilesObj = cJSON_GetObjectItem(moduleObj, "shareFiles");
    if (shareFilesObj == nullptr || !cJSON_IsString(shareFilesObj)) {
        cJSON_Delete(root);
        return "";
    }

    std::string shareFilePath = shareFilesObj->valuestring;
    cJSON_Delete(root);

    std::string actualFilePath = shareFilePath;
    if (shareFilePath.find("$profile:") == 0) {
        actualFilePath = "resources/base/profile/" + shareFilePath.substr(9) + ".json";
    }

    std::string shareFileContent;
    if (!GetFileContentFromHap(hapFilePath, actualFilePath, shareFileContent)) {
        return "";
    }

    std::vector<int8_t> digest;
    if (!ComputeDigest(shareFileContent, digest, signAlgId)) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(digest.data()), digest.size());
}

int VerifyHap::GetProfileContent(const std::string profile, std::string& ret)
{
    cJSON* obj = cJSON_ParseWithOpts(profile.c_str(), nullptr, 1);
    if (obj != nullptr && (cJSON_IsObject(obj) || cJSON_IsArray(obj))) {
        ret = profile;
        cJSON_Delete(obj);
        return 0;
    }
    if (obj != nullptr) {
        cJSON_Delete(obj);
    }
    PKCS7Data p7Data;
    if (p7Data.Parse(profile) < 0) {
        ret = profile;
        return -1;
    }
    if (p7Data.Verify() < 0) {
        PrintErrorNumberMsg("PKCS7_VERIFY_ERROR", VERIFY_ERROR,
                            "Verify profile pkcs7 failed! Profile is invalid");
        ret = profile;
        return -1;
    }
    if (p7Data.GetContent(ret) < 0) {
        PrintErrorNumberMsg("PKCS7_VERIFY_ERROR", VERIFY_ERROR,
                            "Check profile failed, signed profile content is not byte array");
        ret = profile;
        return -1;
    }
    return 0;
}

bool VerifyHap::VerifyAppPkcs7(Pkcs7Context& pkcs7Context, const ByteBuffer& hapSignatureBlock)
{
    const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(hapSignatureBlock.GetBufferPtr());
    uint32_t pkcs7Len = static_cast<unsigned int>(hapSignatureBlock.GetCapacity());
    if (!VerifyHapOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("parse pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("GetCertChains from pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("verify signature failed");
        return false;
    }
    return true;
}

bool VerifyHap::GetDigestAndAlgorithm(Pkcs7Context& digest)
{
    /*
     * contentinfo format:
     * int: version
     * int: block number
     * digest blocks:
     * each digest block format:
     * int: length of sizeof(digestblock) - 4
     * int: Algorithm ID
     * int: length of digest
     * byte[]: digest
     */
     /* length of sizeof(digestblock - 4) */
    int32_t digestBlockLen;
    if (!digest.content.GetInt32(DIGEST_BLOCK_LEN_OFFSET, digestBlockLen)) {
        SIGNATURE_TOOLS_LOGE("get digestBlockLen failed");
        return false;
    }
    /* Algorithm ID */
    if (!digest.content.GetInt32(DIGEST_ALGORITHM_OFFSET, digest.digestAlgorithm)) {
        SIGNATURE_TOOLS_LOGE("get digestAlgorithm failed");
        return false;
    }
    /* length of digest */
    int32_t digestlen;
    if (!digest.content.GetInt32(DIGEST_LEN_OFFSET, digestlen)) {
        SIGNATURE_TOOLS_LOGE("get digestlen failed");
        return false;
    }
    int32_t sum = sizeof(digestlen) + sizeof(digest.digestAlgorithm) + digestlen;
    if (sum != digestBlockLen) {
        SIGNATURE_TOOLS_LOGE("digestBlockLen: %d is not equal to sum: %d",
                             digestBlockLen, sum);
        return false;
    }
    /* set position to the digest start point */
    digest.content.SetPosition(DIGEST_OFFSET_IN_CONTENT);
    /* set limit to the digest end point */
    digest.content.SetLimit(DIGEST_OFFSET_IN_CONTENT + digestlen);
    digest.content.Slice();
    return true;
}

int32_t VerifyHap::WriteVerifyOutput(Pkcs7Context& pkcs7Context, std::vector<int8_t>& profile, Options* options)
{
    if (pkcs7Context.certChain.size() > 0) {
        bool flag = VerifyHap::HapOutPutCertChain(pkcs7Context.certChain[0],
            options->GetString(Options::OUT_CERT_CHAIN));
        if (!flag) {
            SIGNATURE_TOOLS_LOGE("out put cert chain failed");
            return IO_ERROR;
        }
    }
    if (pkcs7Context.p7 == nullptr) {
        std::string p7bContent(profile.begin(), profile.end());
        bool writeFlag = FileUtils::Write(p7bContent, options->GetString(Options::OUT_PROFILE)) < 0;
        if (writeFlag) {
            SIGNATURE_TOOLS_LOGE("p7b write to file falied!\n");
            return IO_ERROR;
        }
        return RET_OK;
    }
    bool pkcs7flag = VerifyHap::HapOutPutPkcs7(pkcs7Context.p7, options->GetString(Options::OUT_PROFILE));
    if (!pkcs7flag) {
        SIGNATURE_TOOLS_LOGE("out put p7b failed");
        return IO_ERROR;
    }
    return RET_OK;
}
} // namespace SignatureTools
} // namespace OHOS
