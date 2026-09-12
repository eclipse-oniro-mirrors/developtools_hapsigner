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

#include "sign_elf.h"
#include <unistd.h>
#include <fstream>

#include "cJSON.h"
#include "file_utils.h"
#include "string_utils.h"
#include "constant.h"
#include "code_signing.h"
#include "param_constants.h"
#include "profile_sign_tool.h"
#include "compare_elf.h"

namespace OHOS {
namespace SignatureTools {

bool SignElf::Sign(SignerConfig& signerConfig, std::map<std::string, std::string>& signParams)
{
    std::string inputFile = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    ELFIO::elfio elfReader;
    if (!elfReader.load(inputFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to load input ELF file");
        return false;
    }
    ElfSignContext ctx;
    if (!ctx.Load(elfReader, inputFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to load ELF context");
        return false;
    }
    if (!ctx.BuildNewShstrtab() || !BuildNewSections(ctx, signerConfig, signParams)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to build new .shstrtab or sign sections");
        return false;
    }
    if (!ctx.FinalizeShstrtab()) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to finalize .shstrtab with magic marker");
        return false;
    }
    std::string outputFile = signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    std::string tmpOutputFile = outputFile;
    if (access(outputFile.c_str(), F_OK) == 0 && FileUtils::IsSameFile(inputFile, outputFile)) {
        tmpOutputFile = inputFile + "-tmp-signed";
    }
    ElfSignWriter writer;
    writer.SetCtx(&ctx);
    int64_t codesignOffset = writer.Write(inputFile, tmpOutputFile);
    if (codesignOffset < 0) {
        unlink(tmpOutputFile.c_str());
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to write signed ELF file");
        return false;
    }
    PrintMsg("add codesign section success");
    // Validate the saved ELF file against original before generating code signature
    CompareElf compareElf(inputFile, tmpOutputFile);
    if (!compareElf.Validate()) {
        SIGNATURE_TOOLS_LOGE("[SignElf] ELF file validation failed");
    }

    std::string selfSign = signParams.at(ParamConstants::PARAM_SELF_SIGN);
    uint64_t csOffset = static_cast<uint64_t>(codesignOffset);
    bool generateCodeSignFlag = GenerateCodeSignByte(signerConfig, tmpOutputFile, csOffset, selfSign);
    if (!generateCodeSignFlag) {
        unlink(tmpOutputFile.c_str());
        return false;
    }
    FileUtils::CopyPermissions(inputFile, tmpOutputFile);
    return FileUtils::CopyTmpFileAndDel(tmpOutputFile, outputFile);
}

bool SignElf::BuildNewSections(ElfSignContext& ctx, SignerConfig& signerConfig,
                               std::map<std::string, std::string>& signParams)
{
    bool isSelfSign = signParams.at(ParamConstants::PARAM_SELF_SIGN) == ParamConstants::SELF_SIGN_TYPE_1;
    if (!isSelfSign) {
        std::string p7b;
        if (!loadProfileAndSign(signerConfig, signParams, p7b)) {
            return false;
        }
        if (!p7b.empty()) {
            if (p7b.size() > MAX_SECTION_SIZE) {
                SIGNATURE_TOOLS_LOGE("[SignElf] Profile content size exceeds maximum allowed section size (10KB)");
                return false;
            }
            std::vector<uint8_t> p7bData(p7b.begin(), p7b.end());
            ctx.AddSignSection(PROFILE_SEC_NAME, 1, p7bData);
            PrintMsg("add profile section success");
        }
        std::string moduleContent;
        if (!loadModule(signParams, moduleContent)) {
            return false;
        }
        if (!moduleContent.empty()) {
            std::string ret;
            if (!WritePermissionVersion(moduleContent, ret)) {
                SIGNATURE_TOOLS_LOGE("[SignElf] Write Permission Version error");
                return false;
            }
            std::vector<uint8_t> permData(ret.begin(), ret.end());
            ctx.AddSignSection(PERMISSION_SEC_NAME, 1, permData);
            PrintMsg("add permission section success");
        }
    }
    std::vector<uint8_t> placeholder(PAGE_SIZE, 0);
    ctx.AddSignSection(CODE_SIGN_SEC_NAME, PAGE_SIZE, placeholder);
    return true;
}

bool SignElf::loadModule(std::map<std::string, std::string>& signParams, std::string& moduleContent)
{
    if (signParams.find(ParamConstants::PARAM_MODULE_FILE) != signParams.end()) {
        std::string modulefilePath = signParams.at(ParamConstants::PARAM_MODULE_FILE);
        if (FileUtils::ReadFile(modulefilePath, moduleContent) < 0) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open module file");
            return false;
        }
    } else {
        SIGNATURE_TOOLS_LOGI("[SignElf] No module file");
    }
    if (moduleContent.size() > MAX_SECTION_SIZE) {
        SIGNATURE_TOOLS_LOGE("[SignElf] moduleContent size exceeds maximum allowed section size (10KB)");
        return false;
    }
    return true;
}

bool SignElf::loadProfileAndSign(SignerConfig& signerConfig, std::map<std::string, std::string>& signParams,
                                 std::string& p7b)
{
    std::string profileContent;
    if (signParams.find(ParamConstants::PARAM_BASIC_PROFILE) != signParams.end()) {
        std::string profilefilePath = signParams.at(ParamConstants::PARAM_BASIC_PROFILE);
        if (FileUtils::ReadFile(profilefilePath, profileContent) < 0) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open profile file");
            return false;
        }
    } else {
        return true;
    }
    std::string profileSigned = signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    if (profileSigned == DEFAULT_PROFILE_SIGNED_0) {
        std::string alg = signParams.at(ParamConstants::PARAM_BASIC_SIGANTURE_ALG);
        if (ProfileSignTool::SignProfile(profileContent, signerConfig.GetSigner(), alg, p7b) < 0) {
            SIGNATURE_TOOLS_LOGE("[SignElf] SignProfile error");
            return false;
        }
    } else {
        p7b = profileContent;
    }
    if (p7b.size() > MAX_SECTION_SIZE) {
        SIGNATURE_TOOLS_LOGE("[SignElf] profileContent size exceeds maximum allowed section size (10KB)");
        return false;
    }
    return true;
}

bool SignElf::GenerateCodeSignByte(SignerConfig& signerConfig, const std::string& inputFile, uint64_t& csOffset,
                                   const std::string& selfSign)
{
    if (csOffset == 0 || (csOffset % PAGE_SIZE) != 0) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Invalid code sign block off %lu, not a multiple of 4096", csOffset);
        return false;
    }
    CodeSigning codeSigning(&signerConfig, (selfSign == ParamConstants::SELF_SIGN_TYPE_1));
    std::vector<int8_t> codesignData;
    bool getElfCodeSignBlockFlag = codeSigning.GetElfCodeSignBlock(inputFile, csOffset, codesignData);
    if (!getElfCodeSignBlockFlag) {
        SIGNATURE_TOOLS_LOGE("[SignElf] get elf code sign block error.");
        return false;
    }
    SIGNATURE_TOOLS_LOGD("[SignElf] elf code sign block off %lu: ,len: %lu .", csOffset, codesignData.size());

    if (codesignData.size() > PAGE_SIZE) {
        SIGNATURE_TOOLS_LOGE("[SignElf] signature size is too large.");
        return false;
    }

    if (!ReplaceDataOffset(inputFile, csOffset, codesignData)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to replace code sign data in file.");
        return false;
    }
    PrintMsg("write code sign data success");
    return true;
}

bool SignElf::ReplaceDataOffset(const std::string& filePath, uint64_t& csOffset, const std::vector<int8_t>& csData)
{
    std::fstream fileStream(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!fileStream) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open file: %s", filePath.c_str());
        return false;
    }

    fileStream.seekp(csOffset, std::ios::beg);
    if (!fileStream) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to seek to offset: %lu", csOffset);
        return false;
    }

    fileStream.write(reinterpret_cast<const char*>(csData.data()), csData.size());
    if (!fileStream) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to write data at offset: %lu", csOffset);
        return false;
    }
    fileStream.flush();
    fileStream.close();
    return true;
}

bool SignElf::WritePermissionVersion(const std::string& moduleContent, std::string& result)
{
    cJSON* root = cJSON_Parse(moduleContent.c_str());
    if (!root) {
        SIGNATURE_TOOLS_LOGE("[SignElf] moduleFile json read error");
        return false;
    }
    cJSON* version = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (!version) {
        cJSON_AddNumberToObject(root, "version", PERMISSION_VERSION);
    } else {
        if (!cJSON_IsNumber(version) || cJSON_GetNumberValue(version) != PERMISSION_VERSION) {
            SIGNATURE_TOOLS_LOGE("[SignElf] the value of 'version' in moduleFile json should be int %d",
                PERMISSION_VERSION);
            cJSON_Delete(root);
            return false;
        }
    }
    char* jsonString = cJSON_PrintUnformatted(root);
    if (!jsonString) {
        cJSON_Delete(root);
        return false;
    }
    result = jsonString;
    free(jsonString);
    cJSON_Delete(root);
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
