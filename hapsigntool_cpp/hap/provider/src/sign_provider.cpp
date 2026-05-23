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
#include "sign_provider.h"

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <cstdio>
#include <cinttypes>
#include <filesystem>
#include <algorithm>
#include <numeric>

#include "cJSON.h"
#include "digest_common.h"
#include "string_utils.h"
#include "file_utils.h"
#include "pkcs7_data.h"
#include "sign_elf.h"
#include "sign_bin.h"
#include "params.h"
#include "constant.h"
#include "verify_hap.h"

namespace OHOS {
namespace SignatureTools {
std::vector<std::string> SignProvider::VALID_SIGN_ALG_NAME = {
    ParamConstants::HAP_SIG_ALGORITHM_SHA256_ECDSA,
    ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA,
    ParamConstants::HAP_SIG_ALGORITHM_SHA512_ECDSA
};

const std::string SignProvider::PROFILE_PREFIX = "$profile:";

bool SignProvider::PrintErrorLog(const std::string& log, const int& errorCode, std::string path)
{
    SIGNATURE_TOOLS_LOGE("%s", std::string("(Error Code: " + std::to_string(errorCode) + ")" + log).c_str());
    if (path != "") {
        remove(path.c_str());
    }
    return false;
}

bool SignProvider::InitSigerConfig(SignerConfig& signerConfig, STACK_OF(X509)* publicCerts, Options* options)
{
    std::optional<X509_CRL*> crl = GetCrl();
    if (!CreateSignerConfigs(publicCerts, crl, options, signerConfig)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] create Signer Configs failed");
        return false;
    }
    int CompatibleVersion;
    if (!StringUtils::CheckStringToInt(signParams.at(ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION),
        CompatibleVersion)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] CompatibleVersion String To int failed");
        return false;
    }
    signerConfig.SetCompatibleVersion(CompatibleVersion);
    return true;
}

int SignProvider::CheckParmaAndInitConfig(SignerConfig& signerConfig, Options* options, std::string& suffix)
{
    STACK_OF(X509)* publicCerts = nullptr;
    int ret = GetX509Certificates(options, &publicCerts);
    if (ret != RET_OK) {
        sk_X509_pop_free(publicCerts, X509_free);
        SIGNATURE_TOOLS_LOGE("SIGNHAP_ERROR get X509 Certificates failed");
        return ret;
    }
    if (!CheckCompatibleVersion()) {
        sk_X509_pop_free(publicCerts, X509_free);
        SIGNATURE_TOOLS_LOGE("check Compatible Version failed!!");
        return COMMAND_PARAM_ERROR;
    }
    if (!InitSigerConfig(signerConfig, publicCerts, options)) {
        SIGNATURE_TOOLS_LOGE("create Signer Configs failed");
        return COMMAND_PARAM_ERROR;
    }
    std::string inputFilePath = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    suffix = FileUtils::GetSuffix(inputFilePath);
    if (suffix == "") {
        SIGNATURE_TOOLS_LOGE("hap format error pleass check!!");
        return COMMAND_PARAM_ERROR;
    }
    return RET_OK;
}

fileIOTuple SignProvider::PrepareIOStreams(const std::string& inputPath,
                                           const std::string& outputPath, bool& ret)
{
    std::shared_ptr<std::ifstream> inputFile = nullptr;
    std::shared_ptr<std::ofstream> outputFile = nullptr;
    std::string tmpOutputFilePath;
    ret = false;
    inputFile = std::make_shared<std::ifstream>(inputPath, std::ios::binary);
    if (!inputFile->good()) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
                            inputPath + " open failed");
        return {nullptr, nullptr, ""};
    }
    if (inputPath == outputPath) {
        std::filesystem::path filePath = outputPath;
        std::filesystem::path directory = filePath.parent_path();
        std::string strDirectory = directory;
        tmpOutputFilePath = strDirectory + '/' + std::string("signedHap") + "." + "hap";
        outputFile = std::make_shared<std::ofstream>(tmpOutputFilePath, std::ios::binary | std::ios::trunc);
        if (!outputFile->good()) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
                                tmpOutputFilePath + " open failed");
            return {nullptr, nullptr, ""};
        }
        ret = true;
    } else {
        outputFile = std::make_shared<std::ofstream>(outputPath, std::ios::binary | std::ios::trunc);
        if (!outputFile->good()) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
                                outputPath + " open failed");
            return {nullptr, nullptr, ""};
        }
        tmpOutputFilePath = outputPath;
    }
    return {inputFile, outputFile, tmpOutputFilePath};
}

bool SignProvider::InitZipOutput(std::shared_ptr<RandomAccessFile> outputHap,
                                 std::shared_ptr<ZipSigner> zip,
                                 std::shared_ptr<std::ifstream> inputStream,
                                 std::shared_ptr<std::ofstream>tmpOutput,
                                 const std::string& Path)
{
    int alignment;
    if (!StringUtils::CheckStringToInt(signParams.at(ParamConstants::PARAM_BASIC_ALIGNMENT), alignment)) {
        SIGNATURE_TOOLS_LOGE("[signHap] alignment String To int failed");
        inputStream->close();
        tmpOutput->close();
        remove(Path.c_str());
        return false;
    }

    if (!CopyFileAndAlignment(*inputStream, *tmpOutput, alignment, *zip)) {
        SIGNATURE_TOOLS_LOGE("[signHap] copy File And Alignment failed");
        inputStream->close();
        tmpOutput->close();
        remove(Path.c_str());
        return false;
    }

    inputStream->close();
    tmpOutput->flush();
    tmpOutput->close();
    if (!outputHap->Init(Path)) {
        SIGNATURE_TOOLS_LOGE("[signHap] init outputFile failed %s", Path.c_str());
        remove(Path.c_str());
        return false;
    }
    return true;
}

bool SignProvider::InitDataSourceContents(RandomAccessFile& outputHap, DataSourceContents& dataSrcContents)
{
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(outputHap);
    // get eocd bytebuffer and eocd offset
    if (!HapSignerBlockUtils::FindEocdInHap(outputHap, dataSrcContents.eocdPair)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "eocd is not found in hap");
        return false;
    }
    dataSrcContents.endOfCentralDir = new ByteBufferDataSource(dataSrcContents.eocdPair.first);
    if (!dataSrcContents.endOfCentralDir) {
        return false;
    }

    // get cd offset
    if (!HapSignerBlockUtils::GetCentralDirectoryOffset(dataSrcContents.eocdPair.first,
                                                        dataSrcContents.eocdPair.second, dataSrcContents.cDOffset)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "get central directory offset failed");
        return false;
    }

    SIGNATURE_TOOLS_LOGI("Central Directory Offset is %" PRId64, dataSrcContents.cDOffset);

    // get beforeCentralDir
    dataSrcContents.beforeCentralDir = outputHapIn->Slice(0, dataSrcContents.cDOffset);
    if (!dataSrcContents.beforeCentralDir) {
        return false;
    }

    // get cd size
    long cDSize;
    if (!HapSignerBlockUtils::GetCentralDirectorySize(dataSrcContents.eocdPair.first, cDSize)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "get central directory size failed");
        return false;
    }

    // get cd buffer
    dataSrcContents.cDByteBuffer = outputHapIn->CreateByteBuffer(dataSrcContents.cDOffset, cDSize);
    if (dataSrcContents.cDByteBuffer.GetCapacity() == 0) {
        return false;
    }
    dataSrcContents.centralDir = new ByteBufferDataSource(dataSrcContents.cDByteBuffer);
    if (!dataSrcContents.centralDir) {
        return false;
    }
    return true;
}

bool SignProvider::Sign(Options* options)
{
    bool isPathOverlap = false;
    SignerConfig signerConfig;
    std::string suffix;
    if (CheckParmaAndInitConfig(signerConfig, options, suffix) != RET_OK) {
        return PrintErrorLog("Check Parma And Init Config failed", COMMAND_PARAM_ERROR);
    }
    // Since CheckParmaAndInitConfig has already validated all parameters, it is possible to directly use at
    std::string inputFilePath = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    auto [inputStream, tmpOutput, tmpOutputFilePath] = PrepareIOStreams(
        inputFilePath,
        signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE), isPathOverlap);

    if (!inputStream || !tmpOutput) {
        return PrintErrorLog("[signHap] Prepare IO Streams failed", IO_ERROR);
    }

    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    if (!InitZipOutput(outputHap, zip, inputStream, tmpOutput, tmpOutputFilePath)) {
        return PrintErrorLog("[signHap] Init Zip Output failed", IO_ERROR);
    }

    DataSourceContents dataSrcContents;
    if (!InitDataSourceContents(*outputHap, dataSrcContents)) {
        return PrintErrorLog("[signHap] Init Data Source Contents failed", ZIP_ERROR, tmpOutputFilePath);
    }

    DataSource* contents[] = {dataSrcContents.beforeCentralDir,
        dataSrcContents.centralDir, dataSrcContents.endOfCentralDir
    };
    if (!AppendPropertyBlock(&signerConfig, tmpOutputFilePath, suffix, dataSrcContents.cDOffset, *zip)) {
        return PrintErrorLog("[SignCode] AppendPropertyBlock failed", SIGN_ERROR, tmpOutputFilePath);
    }

    ByteBuffer signingBlock;
    if (!SignHap::Sign(contents, sizeof(contents) / sizeof(contents[0]), signerConfig, optionalBlocks,
                       signingBlock)) {
        return PrintErrorLog("[SignHap] SignHap Sign failed.", SIGN_ERROR, tmpOutputFilePath);
    }

    int64_t newCentralDirectoryOffset = dataSrcContents.cDOffset + signingBlock.GetCapacity();
    SIGNATURE_TOOLS_LOGI("new Central Directory Offset is %" PRId64, newCentralDirectoryOffset);
    dataSrcContents.eocdPair.first.SetPosition(0);
    if (!ZipUtils::SetCentralDirectoryOffset(dataSrcContents.eocdPair.first, newCentralDirectoryOffset)) {
        return PrintErrorLog("[SignHap] Set Central Directory Offset.", ZIP_ERROR, tmpOutputFilePath);
    }

    if (!OutputSignedFile(outputHap.get(), dataSrcContents.cDOffset, signingBlock, dataSrcContents.centralDir,
                          dataSrcContents.eocdPair.first)) {
        return PrintErrorLog("[SignHap] write output signed file failed.", ZIP_ERROR, tmpOutputFilePath);
    }
    return DoAfterSign(isPathOverlap, tmpOutputFilePath, inputFilePath);
}

bool SignProvider::PrepareReSignBlocks(Options* options)
{
    VerifyHap hapVerify;
    int32_t ret = hapVerify.VerifyBeforeResign(options->GetString(Options::IN_FILE), options);
    if (ret != RET_OK) {
        SIGNATURE_TOOLS_LOGE("hap verify failed !");
        return false;
    }
    
    std::string inputFilePath = options->GetString(Options::IN_FILE);
    RandomAccessFile inputFile;
    if (!inputFile.Init(inputFilePath)) {
        return PrintErrorLog("[ReSignHap] Failed to init input HAP file", IO_ERROR, inputFilePath);
    }
    SignatureInfo hapSignInfo;
    if (!HapSignerBlockUtils::FindHapSignature(inputFile, hapSignInfo)) {
        return PrintErrorLog("[ReSignHap] Failed to find HAP signature", ZIP_ERROR, inputFilePath);
    }

    if (!VerifyHap::IsEnterpriseProfileDistributionType(hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Enterprise Profile failed");
        return false;
    }

    optionalBlocks.clear();

    for (const auto& block : hapSignInfo.optionBlocks) {
        if (block.optionalType == HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID ||
            block.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID ||
            block.optionalType == HapUtils::HAP_PROPERTY_BLOCK_ID) {
            optionalBlocks.push_back(block);
        }
    }
    bool foundOriginalHapSignBlock = false;
    for (const auto& block : optionalBlocks) {
        if (block.optionalType == HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID) {
            foundOriginalHapSignBlock = true;
            break;
        }
    }
    if (!foundOriginalHapSignBlock) {
        OptionalBlock originalMainSignBlock = {
            HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID,
            hapSignInfo.hapSignatureBlock
        };
        optionalBlocks.push_back(originalMainSignBlock);
    }
    return true;
}

bool SignProvider::ReSignHap(Options* options)
{
    if (!PrepareReSignBlocks(options)) {
        return PrintErrorLog("Get Resign Blocks failed", COMMAND_PARAM_ERROR);
    }
    bool isPathOverlap = false;
    SignerConfig signerConfig;
    std::string suffix;
    if (CheckParmaAndInitConfig(signerConfig, options, suffix) != RET_OK) {
        return PrintErrorLog("Check Parma And Init Config failed", COMMAND_PARAM_ERROR);
    }
    std::string inputFilePath = options->GetString(Options::IN_FILE);
    auto [inputStream, tmpOutput, tmpOutputFilePath] = PrepareIOStreams(inputFilePath,
        signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE), isPathOverlap);

    if (!inputStream || !tmpOutput) {
        return PrintErrorLog("[ReSignHap] Prepare IO Streams failed", IO_ERROR);
    }

    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    if (!InitZipOutput(outputHap, zip, inputStream, tmpOutput, tmpOutputFilePath)) {
        return PrintErrorLog("[ReSignHap] Init Zip Output failed", IO_ERROR);
    }

    DataSourceContents dataSrcContents;
    if (!InitDataSourceContents(*outputHap, dataSrcContents)) {
        return PrintErrorLog("[ReSignHap] Init Data Source Contents failed", ZIP_ERROR, tmpOutputFilePath);
    }

    DataSource* contents[] = {dataSrcContents.beforeCentralDir,
        dataSrcContents.centralDir, dataSrcContents.endOfCentralDir};

    if (!AppendReCodeSignBlock(&signerConfig, tmpOutputFilePath, suffix, dataSrcContents.cDOffset, *zip)) {
        return PrintErrorLog("[SignCode] AppendPropertyBlock failed", SIGN_ERROR, tmpOutputFilePath);
    }

    ByteBuffer signingBlock;
    if (!SignHap::SignWithEnterpriseResign(contents, sizeof(contents) / sizeof(contents[0]),
                                           signerConfig, optionalBlocks, signingBlock)) {
        return PrintErrorLog("[ReSignHap] SignHap Sign failed.", SIGN_ERROR, tmpOutputFilePath);
    }

    int64_t newCentralDirectoryOffset = dataSrcContents.cDOffset + signingBlock.GetCapacity();
    SIGNATURE_TOOLS_LOGI("new Central Directory Offset is %" PRId64, newCentralDirectoryOffset);
    dataSrcContents.eocdPair.first.SetPosition(0);
    if (!ZipUtils::SetCentralDirectoryOffset(dataSrcContents.eocdPair.first, newCentralDirectoryOffset)) {
        return PrintErrorLog("[ReSignHap] Set Central Directory Offset.", ZIP_ERROR, tmpOutputFilePath);
    }

    if (!OutputSignedFile(outputHap.get(), dataSrcContents.cDOffset, signingBlock, dataSrcContents.centralDir,
                          dataSrcContents.eocdPair.first)) {
        return PrintErrorLog("[ReSignHap] write output signed file failed.", ZIP_ERROR, tmpOutputFilePath);
    }
    return DoAfterSign(isPathOverlap, tmpOutputFilePath, inputFilePath);
}

bool SignProvider::SignElf(Options* options)
{
    bool isPathOverlap = false;
    STACK_OF(X509)* publicCerts = nullptr;
    int ret = GetX509Certificates(options, &publicCerts);
    if (ret != RET_OK) {
        sk_X509_pop_free(publicCerts, X509_free);
        SIGNATURE_TOOLS_LOGE("[SignElf] get X509 Certificates failed! errorCode:%d", ret);
        return false;
    }
    if (!CheckCompatibleVersion()) {
        sk_X509_pop_free(publicCerts, X509_free);
        SIGNATURE_TOOLS_LOGE("[SignElf] check Compatible Version failed!!");
        return false;
    }

    std::string inputFilePath = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);

    auto [inputStream, tmpOutput, tmpOutputFilePath] =
        PrepareIOStreams(inputFilePath,
                         signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE),
                         isPathOverlap);

    if (!inputStream || !tmpOutput) {
        sk_X509_pop_free(publicCerts, X509_free);
        SIGNATURE_TOOLS_LOGE("[signElf] Prepare IO Streams failed");
        return false;
    }

    SignerConfig signerConfig;
    if (!InitSigerConfig(signerConfig, publicCerts, options)) {
        SIGNATURE_TOOLS_LOGE("SignElf] create Signer Configs failed");
        return false;
    }

    if (!profileContent.empty()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_PROFILE_JSON_CONTENT, profileContent));
    }

    if (!SignElf::Sign(signerConfig, signParams)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] sign elf failed");
        return false;
    }

    return true;
}

bool SignProvider::SignBin(Options* options)
{
    STACK_OF(X509)* x509Certificates = nullptr;
    int ret = GetX509Certificates(options, &x509Certificates);
    if (ret != RET_OK) {
        sk_X509_pop_free(x509Certificates, X509_free);
        SIGNATURE_TOOLS_LOGE("[SignBin] get X509 Certificates failed! errorCode:%d", ret);
        return false;
    }
    if (!CheckCompatibleVersion()) {
        sk_X509_pop_free(x509Certificates, X509_free);
        SIGNATURE_TOOLS_LOGE("check Compatible Version failed!");
        return false;
    }

    SignerConfig signerConfig;
    if (!InitSigerConfig(signerConfig, x509Certificates, options)) {
        SIGNATURE_TOOLS_LOGE("[SignBin] create Signer Configs failed");
        return false;
    }

    bool signFlag = SignBin::Sign(signerConfig, signParams);
    if (!signFlag) {
        SIGNATURE_TOOLS_LOGE("sign bin internal failed");
        return false;
    }

    SIGNATURE_TOOLS_LOGI("sign bin success");
    return true;
}

bool SignProvider::AppendPropertyBlock(SignerConfig* signerConfig, std::string outputFilePath,
                                       const std::string& suffix, int64_t centralDirectoryOffset, ZipSigner& zip)
{
    auto [enableCodeSign, enablePermSign] = CheckSignEnabled();
    if (!enableCodeSign && !enablePermSign) {
        return true;
    }

    std::string suffixTmp = suffix;
    std::transform(suffixTmp.begin(), suffixTmp.end(), suffixTmp.begin(), ::tolower);
    if (!IsCodeSignAndPermSignSupportedFile(suffixTmp)) {
        return true;
    }

    int64_t baseOffset = ComputeBaseOffset(centralDirectoryOffset);
    ByteBuffer codeSignSubBlock;
    ByteBuffer permSignSubBlock;
    int64_t currentOffset = baseOffset;

    SignContext signContext;
    signContext.signerConfig = signerConfig;
    signContext.outputFilePath = outputFilePath;

    if (enableCodeSign) {
        SIGNATURE_TOOLS_LOGI("start code signing.");
        if (!BuildCodeSignSubBlock(suffixTmp, currentOffset, zip, codeSignSubBlock, signContext)) {
            SIGNATURE_TOOLS_LOGE("BuildCodeSignSubBlock Fail.");
            return false;
        }
    }

    if (enablePermSign) {
        SIGNATURE_TOOLS_LOGI("start permission signing.");
        int64_t permSignOffset = currentOffset + PROPERTY_BLOCK_HEADER_SIZE;
        if (!BuildPermSignSubBlock(permSignOffset, zip, permSignSubBlock, signContext)) {
            SIGNATURE_TOOLS_LOGE("BuildPermSignSubBlock Fail.");
            return false;
        }
    }

    int64_t totalPropertySize = codeSignSubBlock.GetCapacity() + permSignSubBlock.GetCapacity();
    SIGNATURE_TOOLS_LOGD("propertyBlock: codeSignSize=%d, permSignSize=%d, totalSize=%lld",
        codeSignSubBlock.GetCapacity(), permSignSubBlock.GetCapacity(), (long long)totalPropertySize);
    if (totalPropertySize > 0) {
        ByteBuffer propertyBlock;
        BuildPropertyBlock(codeSignSubBlock, permSignSubBlock, propertyBlock);
        OptionalBlock tmp = {HapUtils::HAP_PROPERTY_BLOCK_ID, propertyBlock};
        optionalBlocks.insert(optionalBlocks.begin(), tmp);
    } else {
        SIGNATURE_TOOLS_LOGI("[AppendPropertyBlock] propertyBlock is empty, skip adding to optionalBlocks");
    }
    return true;
}

std::pair<bool, bool> SignProvider::CheckSignEnabled()
{
    bool enableCodeSign =
        signParams.at(ParamConstants::PARAM_SIGN_CODE) == CodeSigning::ENABLE_SIGN_CODE_VALUE;
    // Permission signing is performed only when both code signing and permission signing are enabled.
    bool enablePermSign =
        enableCodeSign && signParams.at(ParamConstants::PARAM_PERM_MODE) == ParamConstants::ENABLE_PERM_MODE;
    return {enableCodeSign, enablePermSign};
}

bool SignProvider::IsCodeSignAndPermSignSupportedFile(const std::string& suffixTmp)
{
    if (std::find(CodeSigning::SUPPORT_FILE_FORM.begin(), CodeSigning::SUPPORT_FILE_FORM.end(),
                  suffixTmp) == CodeSigning::SUPPORT_FILE_FORM.end()) {
        SIGNATURE_TOOLS_LOGI("no need to sign code for %s", suffixTmp.c_str());
        return false;
    }
    return true;
}

int64_t SignProvider::ComputeBaseOffset(int64_t centralDirectoryOffset)
{
    return centralDirectoryOffset +
        (PROPERTY_BLOCK_HEADER_SIZE * (optionalBlocks.size() + PROPERTY_BLOCK_COUNT + ADDITIONAL_BLOCK_COUNT));
}

void SignProvider::BuildPropertyBlock(const ByteBuffer& codeSignSubBlock,
                                      const ByteBuffer& permSignSubBlock, ByteBuffer& propertyBlock)
{
    int64_t totalPropertySize = codeSignSubBlock.GetCapacity() + permSignSubBlock.GetCapacity();
    propertyBlock.SetCapacity(totalPropertySize);

    if (codeSignSubBlock.GetCapacity() > 0) {
        propertyBlock.PutData(codeSignSubBlock.GetBufferPtr(), codeSignSubBlock.GetCapacity());
    }
    if (permSignSubBlock.GetCapacity() > 0) {
        propertyBlock.PutData(permSignSubBlock.GetBufferPtr(), permSignSubBlock.GetCapacity());
    }
}

bool SignProvider::BuildCodeSignSubBlock(const std::string& suffix, int64_t codeSignOffset, ZipSigner& zip,
                                         ByteBuffer& subBlock, SignContext& signContext)
{
    CodeSigning codeSigning(signContext.signerConfig);
    if (!codeSigning.GetCodeSignBlock(signContext.outputFilePath, codeSignOffset, suffix,
        profileContent, zip, signContext.codeSignArray)) {
        SIGNATURE_TOOLS_LOGE("Codesigning GetCodeSignBlock Fail.");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("generate codeSignArray finished.");

    subBlock.SetCapacity(signContext.codeSignArray.size() + PROPERTY_BLOCK_HEADER_SIZE);
    subBlock.PutInt32(HapUtils::HAP_CODE_SIGN_BLOCK_ID);
    subBlock.PutInt32(signContext.codeSignArray.size());
    subBlock.PutInt32((int32_t)codeSignOffset);
    subBlock.PutData((const char*)signContext.codeSignArray.data(), signContext.codeSignArray.size());
    return true;
}

bool SignProvider::HasModuleJson(ZipSigner& zip)
{
    for (const auto& entry : zip.GetZipEntries()) {
        std::string fileName = entry->GetZipEntryData()->GetZipEntryHeader()->GetFileName();
        if (fileName == "module.json") {
            return true;
        }
    }
    return false;
}

bool SignProvider::GetModuleJsonContent(const std::string& hapFilePath, std::string& content)
{
    return GetFileContentFromHap(hapFilePath, "module.json", content);
}

bool SignProvider::GetFileContentFromHap(const std::string& hapFilePath,
    const std::string& fileName,
    std::string& content)
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
    long fileLength = zFileInfo.uncompressed_size;
    std::stringbuf sb;
    do {
        readSize = unzReadCurrentFile(zFile, buffer, sizeof(buffer));
        if (readSize > 0) {
            sb.sputn(buffer, readSize);
            fileLength -= readSize;
        }
    } while (fileLength > 0 && readSize > 0);

    if (fileLength > 0) {
        SIGNATURE_TOOLS_LOGE("read %s from zip failed, remaining length: %ld", fileName.c_str(), fileLength);
        unzCloseCurrentFile(zFile);
        unzClose(zFile);
        return false;
    }

    content = sb.str();
    unzCloseCurrentFile(zFile);
    unzClose(zFile);
    return true;
}

bool SignProvider::ComputeDigest(const std::string& content, std::vector<int8_t>& digest, int32_t signAlgId)
{
    if (content.empty()) {
        SIGNATURE_TOOLS_LOGE("content is empty.");
        return false;
    }
    return DoComputeDigest(content.c_str(), content.size(), digest, signAlgId);
}

bool SignProvider::ComputeDigest(const std::vector<int8_t>& data, std::vector<int8_t>& digest, int32_t signAlgId)
{
    if (data.empty()) {
        SIGNATURE_TOOLS_LOGE("data is empty.");
        return false;
    }
    return DoComputeDigest(data.data(), data.size(), digest, signAlgId);
}

bool SignProvider::DoComputeDigest(const void* data, size_t len, std::vector<int8_t>& digest, int32_t signAlgId)
{
    const EVP_MD* hash = (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) ? EVP_sha256() : EVP_sha384();
    int32_t digestLen = (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) ? SHA256_DIGEST_LENGTH : SHA384_DIGEST_LENGTH;
    unsigned char hashResult[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_Digest(data, len, hashResult, &hashLen, hash, nullptr) != 1) {
        return false;
    }

    if (hashLen != static_cast<unsigned int>(digestLen)) {
        SIGNATURE_TOOLS_LOGE("hashLen(%u) != digestLen(%d), hash algorithm mismatch or unexpected output length",
            hashLen, digestLen);
        return false;
    }

    digest.assign(reinterpret_cast<int8_t*>(hashResult), reinterpret_cast<int8_t*>(hashResult) + hashLen);
    return true;
}

bool SignProvider::GetShareFilesFromModuleJson(const std::string& moduleJsonContent,
    std::string& shareFile)
{
    cJSON* root = cJSON_ParseWithOpts(moduleJsonContent.c_str(), nullptr, 1);
    if (root == nullptr) {
        SIGNATURE_TOOLS_LOGE("parse module.json failed.");
        return false;
    }

    cJSON* moduleObj = cJSON_GetObjectItem(root, "module");
    if (moduleObj == nullptr || !cJSON_IsObject(moduleObj)) {
        cJSON_Delete(root);
        return false;
    }

    cJSON* shareFilesObj = cJSON_GetObjectItem(moduleObj, "shareFiles");
    if (shareFilesObj == nullptr || !cJSON_IsString(shareFilesObj)) {
        cJSON_Delete(root);
        return false;
    }

    shareFile = shareFilesObj->valuestring;
    cJSON_Delete(root);
    if (shareFile.empty()) {
        return false;
    }
    return true;
}

bool SignProvider::BuildPermSignSubBlock(int64_t permSignOffset, ZipSigner& zip, ByteBuffer& subBlock,
                                         SignContext& signContext)
{
    if (!HasModuleJson(zip)) {
        SIGNATURE_TOOLS_LOGI("no module.json found, skip permission signing.");
        return true;
    }

    int32_t signAlgId;
    std::string signAlg;
    if (!GetSignAlgorithmInfo(signContext.signerConfig, signAlgId, signAlg)) {
        return false;
    }

    std::string moduleJsonContent;
    if (!GetModuleJsonContent(signContext.outputFilePath, moduleJsonContent)) {
        SIGNATURE_TOOLS_LOGE("get module.json content failed.");
        return false;
    }

    std::vector<std::pair<int, std::vector<int8_t>>> digestItems;
    if (!ComputePermissionDigests(signContext.outputFilePath, moduleJsonContent, digestItems, signAlgId,
                                  signContext.codeSignArray)) {
        return false;
    }

    int32_t digestSize = (signAlgId == ALGORITHM_SHA256_WITH_ECDSA) ? SHA256_DIGEST_LENGTH : SHA384_DIGEST_LENGTH;

    PermSignData signData = {signAlgId, signAlg, digestSize, digestItems, ""};
    std::string unsignedData = BuildPermUnsignedData(signData);
    if (unsignedData.empty()) {
        SIGNATURE_TOOLS_LOGE("build permission sign data to sign failed.");
        return false;
    }

    std::shared_ptr<Signer> signer = signContext.signerConfig->GetSigner();
    if (signer == nullptr) {
        SIGNATURE_TOOLS_LOGE("get signer failed.");
        return false;
    }

    std::string signature = signer->GetSignature(unsignedData, signAlg);
    if (signature.empty()) {
        SIGNATURE_TOOLS_LOGE("generate permission signature failed.");
        return false;
    }

    signData.signature = signature;
    return BuildPermSignBlock(permSignOffset, unsignedData, signature, subBlock);
}

bool SignProvider::ComputePermissionDigests(const std::string& outputFilePath,
                                            const std::string& moduleJsonContent,
                                            std::vector<std::pair<int, std::vector<int8_t>>>& digestItems,
                                            int32_t signAlgId,
                                            const std::vector<int8_t>& codeSignArray)
{
    std::vector<int8_t> provisionDigest;
    if (!ComputeDigest(profileContent, provisionDigest, signAlgId)) {
        SIGNATURE_TOOLS_LOGE("compute provision digest failed.");
        return false;
    }
    digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_PROVISION, provisionDigest});

    std::vector<int8_t> moduleJsonDigest;
    if (!ComputeDigest(moduleJsonContent, moduleJsonDigest, signAlgId)) {
        SIGNATURE_TOOLS_LOGE("compute module.json digest failed.");
        return false;
    }
    digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_MODULE_JSON, moduleJsonDigest});

    if (!codeSignArray.empty()) {
        std::vector<int8_t> codeSignDigest;
        if (!ComputeDigest(codeSignArray, codeSignDigest, signAlgId)) {
            SIGNATURE_TOOLS_LOGE("compute code sign block digest failed.");
            return false;
        }
        digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_CODE_SIGN_BLOCK, codeSignDigest});
    }

    std::string shareFile;
    if (GetShareFilesFromModuleJson(moduleJsonContent, shareFile)) {
        ProcessShareFileDigests(outputFilePath, shareFile, signAlgId, digestItems);
    }
    return true;
}

void SignProvider::ProcessShareFileDigests(const std::string& outputFilePath,
    const std::string& shareFile, int32_t signAlgId,
    std::vector<std::pair<int, std::vector<int8_t>>>& digestItems)
{
    std::string actualFilePath = shareFile;
    if (shareFile.find(PROFILE_PREFIX) == 0) {
        actualFilePath =
            "resources/base/profile/" + shareFile.substr(PROFILE_PREFIX.size()) + ".json";
    }
    std::string shareFileContent;
    if (GetFileContentFromHap(outputFilePath, actualFilePath, shareFileContent)) {
        std::vector<int8_t> shareFileDigest;
        if (!ComputeDigest(shareFileContent, shareFileDigest, signAlgId)) {
            SIGNATURE_TOOLS_LOGW("compute %s digest failed.", actualFilePath.c_str());
            return;
        }
        digestItems.push_back({HapUtils::PERMISSION_SIGN_DIGEST_TYPE_SHARED_FILE, shareFileDigest});
    }
}

bool SignProvider::GetSignAlgorithmInfo(SignerConfig* signerConfig, int32_t& signAlgId, std::string& signAlg)
{
    std::vector<SignatureAlgorithmHelper> sigs = signerConfig->GetSignatureAlgorithms();
    if (sigs.size() != 1) {
        SIGNATURE_TOOLS_LOGE("get signature algorithm failed.");
        return false;
    }
    signAlgId = static_cast<int32_t>(sigs[0].m_id);
    if (signAlgId == static_cast<int32_t>(SignatureAlgorithmId::ECDSA_WITH_SHA256)) {
        signAlg = SIGN_ALG_SHA256;
    } else if (signAlgId == static_cast<int32_t>(SignatureAlgorithmId::ECDSA_WITH_SHA384)) {
        signAlg = SIGN_ALG_SHA384;
    } else {
        SIGNATURE_TOOLS_LOGE("unsupported sign algorithm id: 0x%08x", signAlgId);
        return false;
    }
    return true;
}

std::string SignProvider::BuildPermUnsignedData(const PermSignData& signData)
{
    const std::vector<int8_t>& magic = HapUtils::GetPermissionSignMagic();
    int digestItemsCount = signData.digestItems.size();
    int digestLen = digestItemsCount * (4 + signData.digestSize);

    std::string signDataBytes;
    signDataBytes.append(reinterpret_cast<const char*>(magic.data()), magic.size());
    signDataBytes.append(reinterpret_cast<const char*>(&signData.signAlgId), sizeof(signData.signAlgId));
    signDataBytes.append(reinterpret_cast<const char*>(&digestLen), sizeof(digestLen));
    int16_t num = static_cast<int16_t>(digestItemsCount);
    signDataBytes.append(reinterpret_cast<const char*>(&num), sizeof(num));
    for (const auto& item : signData.digestItems) {
        signDataBytes.append(reinterpret_cast<const char*>(&item.first), sizeof(item.first));
        signDataBytes.append(reinterpret_cast<const char*>(item.second.data()), signData.digestSize);
    }
    return signDataBytes;
}

bool SignProvider::BuildPermSignBlock(int64_t permSignOffset, const std::string& unsignedData,
    const std::string& signature, ByteBuffer& subBlock)
{
    int sigLen = signature.size();
    int permSignDataLen = unsignedData.size() + 4 + sigLen;
    int totalSize = PROPERTY_BLOCK_HEADER_SIZE + permSignDataLen;

    subBlock.SetCapacity(totalSize);
    subBlock.PutInt32(HapUtils::PERMISSION_SIGN_BLOCK_ID);
    subBlock.PutInt32(permSignDataLen);
    subBlock.PutInt32((int32_t)permSignOffset);

    subBlock.PutData(unsignedData.data(), unsignedData.size());
    subBlock.PutInt32(sigLen);
    subBlock.PutData((const char*)signature.data(), sigLen);
    return true;
}

bool SignProvider::AppendReCodeSignBlock(SignerConfig* signerConfig, std::string outputFilePath,
    const std::string& suffix, int64_t centralDirectoryOffset, ZipSigner& zip)
{
    SIGNATURE_TOOLS_LOGI("start re code signing.");
    std::string suffixTmp = suffix;
    std::transform(suffixTmp.begin(), suffixTmp.end(), suffixTmp.begin(), ::tolower);

    bool enablePermSign =
        signParams.at(ParamConstants::PARAM_PERM_MODE) == ParamConstants::ENABLE_PERM_MODE;
    int64_t codeSignOffset = ComputeCodeSignOffset(centralDirectoryOffset);

    SignContext signContext;
    signContext.signerConfig = signerConfig;
    signContext.outputFilePath = outputFilePath;

    CodeSigning codeSigning(signContext.signerConfig);
    if (!codeSigning.GetCodeSignBlock(signContext.outputFilePath, codeSignOffset, suffixTmp,
        profileContent, zip, signContext.codeSignArray)) {
        SIGNATURE_TOOLS_LOGE("Codesigning getCodeSignBlock Fail.");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("generate codeSignArray finished.");

    auto codeSignResult = std::make_unique<ByteBuffer>(signContext.codeSignArray.size() + PROPERTY_BLOCK_HEADER_SIZE);
    codeSignResult->PutInt32(HapUtils::HAP_CODE_SIGN_BLOCK_ID);
    codeSignResult->PutInt32(signContext.codeSignArray.size());
    codeSignResult->PutInt32((int32_t)codeSignOffset);
    codeSignResult->PutData(signContext.codeSignArray.data(), signContext.codeSignArray.size());

    std::unique_ptr<ByteBuffer> permSignResult;
    if (enablePermSign) {
        SIGNATURE_TOOLS_LOGI("start re permission signing.");
        int64_t permSignOffset = codeSignResult->GetCapacity() + PROPERTY_BLOCK_HEADER_SIZE;
        ByteBuffer permSignSubBlock;
        if (!BuildPermSignSubBlock(permSignOffset, zip, permSignSubBlock, signContext)) {
            SIGNATURE_TOOLS_LOGE("BuildPermSignSubBlock for re-sign Fail.");
            return false;
        }
        if (permSignSubBlock.GetCapacity() > 0) {
            permSignResult = std::make_unique<ByteBuffer>(permSignSubBlock.GetCapacity());
            permSignResult->PutData(permSignSubBlock.GetBufferPtr(), permSignSubBlock.GetCapacity());
        }
    }

    int64_t totalSize = codeSignResult->GetCapacity() + (permSignResult ? permSignResult->GetCapacity() : 0);
    auto result = std::make_unique<ByteBuffer>(totalSize);
    result->PutData(codeSignResult->GetBufferPtr(), codeSignResult->GetCapacity());
    if (permSignResult) {
        result->PutData(permSignResult->GetBufferPtr(), permSignResult->GetCapacity());
    }

    OptionalBlock tmp = {HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID, *result};
    optionalBlocks.push_back(tmp);
    return true;
}

int64_t SignProvider::ComputeCodeSignOffset(int64_t centralDirectoryOffset)
{
    int64_t optionalBlockSize = std::accumulate(optionalBlocks.begin(), optionalBlocks.end(), 0,
        [](int64_t sum, const auto& elem) {
            return sum + elem.optionalBlockValue.GetCapacity();
        });
    return centralDirectoryOffset + optionalBlockSize +
        PROPERTY_BLOCK_HEADER_SIZE * (optionalBlocks.size() + PROPERTY_BLOCK_COUNT + ADDITIONAL_BLOCK_COUNT);
}

bool SignProvider::CreateSignerConfigs(STACK_OF(X509)* certificates,
    const std::optional<X509_CRL*>& crl, Options* options, SignerConfig& inOut)
{
    inOut.FillParameters(signParams);
    inOut.SetCertificates(certificates);
    inOut.SetOptions(options);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    SignatureAlgorithmHelper alg;
    // Since CheckParmaAndInitConfig has already validated all parameters, it is possible to directly use at
    if (!Params::GetSignatureAlgorithm(signParams.at(ParamConstants::PARAM_BASIC_SIGANTURE_ALG),
                                       alg)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] get Signature Algorithm failed");
        return false;
    }
    signatureAlgorithms.push_back(alg);
    inOut.SetSignatureAlgorithms(signatureAlgorithms);
    if (crl.has_value()) {
        SIGNATURE_TOOLS_LOGE("not support crl");
        return false;
    }
    return true;
}

int SignProvider::LoadOptionalBlocks()
{
    int ret = RET_OK;
    if (auto property = signParams.find(ParamConstants::PARAM_BASIC_PROPERTY);
        property != signParams.end()) {
        if ((ret = LoadOptionalBlock(property->second, HapUtils::HAP_PROPERTY_BLOCK_ID)) != RET_OK)
            return ret;
    }
    if (auto profile = signParams.find(ParamConstants::PARAM_BASIC_PROFILE); profile != signParams.end()) {
        if ((ret = LoadOptionalBlock(profile->second, HapUtils::HAP_PROFILE_BLOCK_ID)) != RET_OK)
            return ret;
    }
    if (auto proofOfRotation = signParams.find(ParamConstants::PARAM_BASIC_PROOF);
        proofOfRotation != signParams.end()) {
        if ((LoadOptionalBlock(proofOfRotation->second, HapUtils::HAP_PROOF_OF_ROTATION_BLOCK_ID)) != RET_OK)
            return ret;
    }
    return ret;
}

int SignProvider::LoadOptionalBlock(const std::string& file, int type)
{
    if (file.empty())
        return RET_OK;
    if (!CheckFile(file)) {
        SIGNATURE_TOOLS_LOGE("check file failed. Invalid file: %s, file type: %d",
                             file.c_str(), type);
        return FILE_NOT_FOUND;
    }
    ByteBuffer optionalBlockBuffer;
    if (!HapUtils::ReadFileToByteBuffer(file, optionalBlockBuffer))
        return IO_ERROR;
    if (optionalBlockBuffer.GetCapacity() == 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, file + " is empty!");
        return IO_ERROR;
    }
    optionalBlocks.push_back({type, optionalBlockBuffer});
    return RET_OK;
}

std::optional<X509_CRL*> SignProvider::GetCrl()
{
    return std::nullopt;
}

bool SignProvider::CheckFile(const std::string& filePath)
{
    if (filePath.empty()) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "file name is null.");
        return false;
    }
    if (!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath)) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, filePath + " not exist or can not read!");
        return false;
    }
    return true;
}

int SignProvider::GetX509Certificates(Options* options, STACK_OF(X509)** X509Vec)
{
    int ret = RET_OK;
    // 1.check the parameters
    if (!CheckParams(options)) {
        SIGNATURE_TOOLS_LOGE("Check Params failed please check");
        return COMMAND_ERROR;
    }
    // 2.get x509 verify certificate
    ret = GetPublicCerts(options, X509Vec);
    if (ret != RET_OK) {
        SIGNATURE_TOOLS_LOGE("Get Public Certs please check");
        return ret;
    }
    // 3. load optionalBlocks
    ret = LoadOptionalBlocks();
    if (ret != RET_OK) {
        SIGNATURE_TOOLS_LOGE("Load Optional Blocks please check");
        return ret;
    }
    std::string inForm = options->GetString(Options::INFORM);
    std::string profileFile = options->GetString(Options::PROFILE_FILE);
    if (StringUtils::CaseCompare(inForm, ELF) && FileUtils::IsEmpty(profileFile)) {
        return ret;
    }
    // 4. check Profile Valid
    if ((ret = CheckProfileValid(*X509Vec)) < 0) {
        SIGNATURE_TOOLS_LOGE("profile check error");
        sk_X509_pop_free(*X509Vec, X509_free);
        *X509Vec = nullptr;
        return ret;
    }
    return ret;
}

int SignProvider::GetPublicCerts(Options* options, STACK_OF(X509)** ret)
{
    std::string appCertFileName = options->GetString(Options::APP_CERT_FILE);
    if (appCertFileName.empty()) {
        SIGNATURE_TOOLS_LOGI("appCertFile param can not find,may be is RemoteSigner");
        return RET_OK;
    }
    return GetCertificateChainFromFile(appCertFileName, ret);
}

int SignProvider::GetCertificateChainFromFile(const std::string& certChianFile, STACK_OF(X509)** ret)
{
    return GetCertListFromFile(certChianFile, ret);
}

int SignProvider::GetCertListFromFile(const std::string& certsFile, STACK_OF(X509)** ret)
{
    X509* cert = nullptr;
    *ret = sk_X509_new(nullptr);
    if (*ret == nullptr) {
        PrintErrorNumberMsg("RET_FAILED", RET_FAILED, "get CertList FromFile [sk_X509_new] failed");
        return RET_FAILED;
    }
    BIO* certBio = BIO_new_file(certsFile.c_str(), "rb");
    if (!certBio) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
                            std::string("get CertList from file ") + certsFile + " failed");
        sk_X509_free(*ret);
        return IO_ERROR;
    }
    while (1) {
        cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
        if (cert == nullptr)
            break;
        sk_X509_push(*ret, cert);
    }
    if (PKCS7Data::SortX509Stack(*ret) != RET_OK) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
            "Input certificate file do not include a valid certificate chains");
        return CERTIFICATE_ERROR;
    }
    BIO_free(certBio);
    return RET_OK;
}

bool SignProvider::DoAfterSign(bool isPathOverlap, const std::string& tmpOutputFile, const std::string& inputFilePath)
{
    if (isPathOverlap) {
        remove(inputFilePath.c_str());
        if (rename(tmpOutputFile.c_str(), inputFilePath.c_str()) != 0) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
                                "File name " + tmpOutputFile + " rename to " + inputFilePath + " failed!");
            return false;
        }
    }
    return true;
}

bool SignProvider::CopyFileAndAlignment(std::ifstream& input, std::ofstream& tmpOutput, int alignment, ZipSigner& zip)
{
    if (!zip.Init(input)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "zip init failed");
        return false;
    }
    zip.Alignment(alignment);
    zip.RemoveSignBlock();
    if (!zip.ToFile(input, tmpOutput)) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "zip write to file failed");
        return false;
    }
    return true;
}

bool SignProvider::SetSignParams(Options* options, std::unordered_set<std::string>& paramSet)
{
    for (auto it = options->begin(); it != options->end(); it++) {
        if (paramSet.find(it->first) != paramSet.end()) {
            size_t size = it->first.size();
            std::string str = it->first.substr(size - 3);
            if (str != "Pwd") {
                this->signParams.insert(std::make_pair(it->first, options->GetString(it->first)));
            }
        }
    }
    return true;
}

bool SignProvider::CheckParams(Options* options)
{
    std::vector<std::string> paramFileds;
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_ALIGNMENT);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_SIGANTURE_ALG);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_INPUT_FILE);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PRIVATE_KEY);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROFILE);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROOF);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROPERTY);
    paramFileds.emplace_back(ParamConstants::PARAM_REMOTE_SERVER);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_PUBLIC_CERT);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION);
    paramFileds.emplace_back(ParamConstants::PARAM_SIGN_CODE);
    paramFileds.emplace_back(ParamConstants::PARAM_PERM_MODE);
    paramFileds.emplace_back(ParamConstants::PARAM_IN_FORM);

    std::unordered_set<std::string> paramSet = Params::InitParamField(paramFileds);
    for (auto it = options->begin(); it != options->end(); it++) {
        if (paramSet.find(it->first) != paramSet.end()) {
            signParams.insert(std::make_pair(it->first, options->GetString(it->first)));
        }
    }

    if (signParams.find(ParamConstants::PARAM_BASIC_PROFILE_SIGNED) == signParams.end()
        || signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED).empty()) {
        signParams[ParamConstants::PARAM_BASIC_PROFILE_SIGNED] = "1";
    }
    if (!CheckSignCode()) {
        SIGNATURE_TOOLS_LOGE("signCode Parameter check error, signCode must is 0 or 1");
        return false;
    }
    if (!CheckPermMode()) {
        SIGNATURE_TOOLS_LOGE("permSign Parameter check error, permSign must is 0 or 1");
        return false;
    }
    if (!CheckSignatureAlg()) {
        SIGNATURE_TOOLS_LOGE("signAlg Parameter is not support");
        return false;
    }
    CheckSignAlignment();
    return true;
}

bool SignProvider::CheckSignCode()
{
    if (signParams.find(ParamConstants::PARAM_SIGN_CODE) == signParams.end()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_SIGN_CODE, ParamConstants::ENABLE_SIGN_CODE));
        return true;
    }
    std::string codeSign = signParams[ParamConstants::PARAM_SIGN_CODE];
    if ((codeSign != ParamConstants::ENABLE_SIGN_CODE) && (codeSign != ParamConstants::DISABLE_SIGN_CODE)) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "signCode Parameter must 0 or 1, you put is " + codeSign);
        return false;
    }
    return true;
}

bool SignProvider::CheckPermMode()
{
    if (signParams.find(ParamConstants::PARAM_PERM_MODE) == signParams.end()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_PERM_MODE, ParamConstants::ENABLE_PERM_MODE));
        return true;
    }
    std::string permMode = signParams[ParamConstants::PARAM_PERM_MODE];
    if ((permMode != ParamConstants::ENABLE_PERM_MODE) && (permMode != ParamConstants::DISABLE_PERM_MODE)) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "permSign Parameter must 0 or 1, you put is " + permMode);
        return false;
    }
    return true;
}

bool SignProvider::CheckSignatureAlg()
{
    std::string signAlg = signParams[ParamConstants::PARAM_BASIC_SIGANTURE_ALG];
    // Remove leading spaces
    size_t start = signAlg.find_first_not_of(" ");
    if (start != std::string::npos) {
        signAlg = signAlg.substr(start);
    }
    // Remove trailing spaces
    size_t end = signAlg.find_last_not_of(" ");
    if (end != std::string::npos) {
        signAlg.resize(end + 1);
    }
    for (auto it = VALID_SIGN_ALG_NAME.begin(); it != VALID_SIGN_ALG_NAME.end(); it++) {
        if (StringUtils::CaseCompare(*it, signAlg)) {
            return true;
        }
    }
    PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                        "signAlg Parameter is only support [SHA256withECDSA / SHA384withECDSA]");
    return false;
}

void SignProvider::CheckSignAlignment()
{
    if (signParams.find(ParamConstants::PARAM_BASIC_ALIGNMENT) == signParams.end()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_BASIC_ALIGNMENT, ParamConstants::ALIGNMENT));
    }
}

bool SignProvider::CheckCompatibleVersion()
{
    auto it = signParams.find(ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION);
    if (it == signParams.end()) {
        signParams[ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION] = "9";
        return true;
    }
    const std::string& compatibleApiVersionVal = it->second;
    int compatibleApiVersion;
    if (!StringUtils::CheckStringToInt(compatibleApiVersionVal, compatibleApiVersion)) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "compatibleVersion Parameter is must integer");
        return false;
    }
    return true;
}

bool SignProvider::OutputSignedFile(RandomAccessFile* outputHap,
                                    long centralDirectoryOffset,
                                    ByteBuffer& signingBlock,
                                    ByteBufferDataSource* centralDirectory,
                                    ByteBuffer& eocdBuffer)
{
    std::shared_ptr<RandomAccessFileOutput> outputHapOut =
        std::make_shared<RandomAccessFileOutput>(outputHap, centralDirectoryOffset);
    if (!outputHapOut->Write(signingBlock)) {
        SIGNATURE_TOOLS_LOGE("output hap file write signingBlock failed");
        return false;
    }
    if (!outputHapOut->Write(centralDirectory->GetByteBuffer())) {
        SIGNATURE_TOOLS_LOGE("output hap file write central directory failed");
        return false;
    }
    if (!outputHapOut->Write(eocdBuffer) != 0) {
        SIGNATURE_TOOLS_LOGE("output hap file write eocd failed");
        return false;
    }
    return true;
}

X509* SignProvider::GetCertificate(const std::string& certificate)const
{
    BIO* in = BIO_new_mem_buf(certificate.data(), certificate.size());
    if (!in) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "bio new error ,get ceritificate from base64 certificate failed");
        return NULL;
    }
    X509* cert = NULL;
    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(in);
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR,
                            "read no cert from base64 certificate failed");
        return NULL;
    }
    BIO_free(in);
    return cert;
}

std::string SignProvider::GetCertificateCN(X509* cert)const
{
    X509_NAME* name = NULL;
    int len = 0;
    std::string ret;
    if (cert == NULL) {
        return "";
    }
    name = X509_get_subject_name(cert);
    if (!name) {
        SIGNATURE_TOOLS_LOGE("name is NULL,get X509_NAME from cert failed");
    }
    len = X509_NAME_get_text_by_NID(name, NID_countryName, NULL, 0);
    if (len <= 0) {
        return "";
    }
    ret.resize(len + 1);
    if (X509_NAME_get_text_by_NID(name, NID_countryName, &ret[0], len + 1) != len) {
        return "";
    }
    return ret;
}

std::string SignProvider::FindProfileFromOptionalBlocks()const
{
    std::string profile;
    for (const OptionalBlock& optionalBlock : optionalBlocks) {
        if (optionalBlock.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            profile = std::string(optionalBlock.optionalBlockValue.GetBufferPtr(),
                                  optionalBlock.optionalBlockValue.GetCapacity());
        }
    }
    return profile;
}

int SignProvider::CheckProfileValid(STACK_OF(X509)* inputCerts)
{
    std::string profile = FindProfileFromOptionalBlocks();
    std::map<std::string, std::string>::const_iterator ite =
        signParams.find(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    if (ite == signParams.end()) {
        PrintErrorNumberMsg("INVALIDPARAM_ERROR", INVALIDPARAM_ERROR,
                            "find PARAM_BASIC_PROFILE_SIGNED failed");
        return INVALIDPARAM_ERROR;
    }
    bool isProfileWithoutSign = (ParamConstants::DISABLE_SIGN_CODE == ite->second);
    if (!isProfileWithoutSign) {
        PKCS7Data p7Data;
        if (p7Data.Parse(profile) < 0) {
            SIGNATURE_TOOLS_LOGE("Parse profile error.");
            return PARSE_ERROR;
        }
        if (p7Data.Verify() < 0) {
            SIGNATURE_TOOLS_LOGE("Verify profile pkcs7 failed! Profile is invalid.");
            return VERIFY_ERROR;
        }
        profileContent.clear();
        if (p7Data.GetContent(profileContent) < 0) {
            SIGNATURE_TOOLS_LOGE("get content data failed");
            return  INVALIDPARAM_ERROR;
        }
    } else {
        profileContent = profile;
    }

    ProfileInfo info;
    if (ParseProvision(profileContent, info) != PROVISION_OK) {
        SIGNATURE_TOOLS_LOGE("parse provision error");
        return PARSE_ERROR;
    }
    if (CheckProfileInfo(info, inputCerts) < 0) {
        SIGNATURE_TOOLS_LOGE("Check Profile Info error");
        return RET_FAILED;
    }
    return 0;
}

int SignProvider::CheckProfileInfo(const ProfileInfo& info, STACK_OF(X509)* inputCerts)const
{
    X509* certInProfile = NULL;
    if (info.type == ProvisionType::RELEASE) {
        certInProfile = GetCertificate(info.bundleInfo.distributionCertificate);
    } else if (info.type == ProvisionType::DEBUG) {
        certInProfile = GetCertificate(info.bundleInfo.developmentCertificate);
    } else {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "Unsupported profile type!");
        return NOT_SUPPORT_ERROR;
    }
    if (sk_X509_num(inputCerts) > 0 && !CheckInputCertMatchWithProfile(sk_X509_value(inputCerts, 0),
                                                                       certInProfile)) {
        X509_free(certInProfile);
        SIGNATURE_TOOLS_LOGE("input certificates do not match with profile!");
        return RET_FAILED;
    }
    std::string cn = GetCertificateCN(certInProfile);
    X509_free(certInProfile);
    SIGNATURE_TOOLS_LOGI("certificate in profile: %s", cn.c_str());
    if (cn.empty()) {
        PrintErrorNumberMsg("CERTIFICATE_ERROR", CERTIFICATE_ERROR, "Common name of certificate is empty!");
        return CERTIFICATE_ERROR;
    }
    return 0;
}

bool SignProvider::CheckInputCertMatchWithProfile(X509* inputCert, X509* certInProfile)const
{
    return true;
}
} // namespace SignatureTools
} // namespace OHOS