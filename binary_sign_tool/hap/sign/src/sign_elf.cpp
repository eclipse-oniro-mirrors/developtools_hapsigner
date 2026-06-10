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
constexpr size_t MAX_SECTION_SIZE = static_cast<size_t>(10240);

bool SignElf::Sign(SignerConfig& signerConfig, std::map<std::string, std::string>& signParams)
{
    std::string inputFile = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    ELFIO::elfio elfReader;
    if (!elfReader.load(inputFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to load input ELF file");
        return false;
    }
    elfReader.sections.del_last(CODE_SIGN_SEC_NAME);
    elfReader.sections.del_last(PERMISSION_SEC_NAME);
    elfReader.sections.del_last(PROFILE_SEC_NAME);
    bool writeProfilFlag = WriteSecDataToFile(elfReader, signerConfig, signParams);
    if (!writeProfilFlag) {
        SIGNATURE_TOOLS_LOGE("[SignElf] WriteSecDataToFile error");
        return false;
    }
    std::string outputFile = signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    std::string tmpOutputFile = outputFile;
    if (access(outputFile.c_str(), F_OK) == 0 && FileUtils::IsSameFile(inputFile, outputFile)) {
        tmpOutputFile = inputFile + "-tmp-signed";
    }
    uint64_t csOffset = 0;
    bool writeCodeSignFlag = WriteCodeSignBlock(elfReader, tmpOutputFile, csOffset);
    if  (!writeCodeSignFlag) {
        unlink(tmpOutputFile.c_str());
        SIGNATURE_TOOLS_LOGE("[SignElf] WriteCodeSignBlock error");
        return false;
    }

    // Validate the saved ELF file against original before generating code signature
    CompareElf compareElf(inputFile, tmpOutputFile);
    if (!compareElf.Validate()) {
        SIGNATURE_TOOLS_LOGE("[SignElf] ELF file validation failed");
    }

    std::string selfSign = signParams.at(ParamConstants::PARAM_SELF_SIGN);
    bool generateCodeSignFlag = GenerateCodeSignByte(signerConfig, tmpOutputFile, csOffset, selfSign);
    if  (!generateCodeSignFlag) {
        unlink(tmpOutputFile.c_str());
        return false;
    }
    FileUtils::CopyPermissions(inputFile, tmpOutputFile);
    return FileUtils::CopyTmpFileAndDel(tmpOutputFile, outputFile);
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

bool SignElf::isExecElf(ELFIO::elfio& reader)
{
    ELFIO::Elf64_Half eType = reader.get_type();
    if (eType == ELFIO::ET_EXEC) {
        return true;
    }
    if (eType == ELFIO::ET_DYN && reader.get_entry() > 0) {
        return true;
    }
    return false;
}

bool SignElf::WriteCodeSignBlock(ELFIO::elfio& reader, std::string& outputFile, uint64_t& csOffset)
{
    ELFIO::section* sec = reader.sections[CODE_SIGN_SEC_NAME];
    if (sec) {
        SIGNATURE_TOOLS_LOGE("[SignElf] .codesign section already exists");
        return false;
    }
    sec = reader.sections.add(CODE_SIGN_SEC_NAME);
    if (!sec) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to create .codesign section");
        return false;
    }
    sec->set_type(ELFIO::SHT_PROGBITS);
    sec->set_addr_align(PAGE_SIZE);
    char codesignData[PAGE_SIZE];
    sec->set_data(codesignData, PAGE_SIZE);

    if (!reader.save(outputFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to save 4K data to .codesign section");
        return false;
    }
    ELFIO::Elf64_Off secOff = sec->get_offset();
    csOffset = secOff;
    PrintMsg("add codesign section success");
    SIGNATURE_TOOLS_LOGD("[SignElf] .codesign section offset: %lu, size: %lu", secOff, sec->get_size());
    return true;
}

bool SignElf::WriteSection(ELFIO::elfio& reader, const std::string& content, const std::string& secName)
{
    ELFIO::section* sec = reader.sections[secName];
    if (sec) {
        SIGNATURE_TOOLS_LOGE("[SignElf] %s section already exists", secName.c_str());
        return false;
    }
    sec = reader.sections.add(secName);
    if (!sec) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to create %s section", secName.c_str());
        return false;
    }
    sec->set_type(ELFIO::SHT_PROGBITS);
    sec->set_addr_align(1);
    sec->set_data(content);
    return true;
}

bool SignElf::WriteSecDataToFile(ELFIO::elfio& reader, SignerConfig& signerConfig,
                                 std::map<std::string, std::string>& signParams)
{
    if (signParams.at(ParamConstants::PARAM_SELF_SIGN) == ParamConstants::SELF_SIGN_TYPE_1) {
        return true;
    }
    std::string p7b;
    if (!loadProfileAndSign(signerConfig, signParams, p7b)) {
        return false;
    }
    if (!p7b.empty()) {
        if (WriteSection(reader, p7b, PROFILE_SEC_NAME)) {
            PrintMsg("add profile section success");
        } else {
            return false;
        }
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
        if (WriteSection(reader, ret, PERMISSION_SEC_NAME)) {
            PrintMsg("add permission section success");
        } else {
            return false;
        }
    }
    return true;
}

bool SignElf::GenerateCodeSignByte(SignerConfig& signerConfig, const std::string& inputFile, uint64_t& csOffset,
                                   const std::string& selfSign)
{
    // cs offset > 0 and 4K alignment
    if (csOffset == 0 || (csOffset % PAGE_SIZE) != 0) {
        SIGNATURE_TOOLS_LOGE("[SignElf] csOffset is not 4K alignment");
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