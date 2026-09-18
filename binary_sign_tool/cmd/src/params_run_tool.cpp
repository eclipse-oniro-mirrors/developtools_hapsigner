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

#include "params_run_tool.h"
#include <unistd.h>
#include <memory>
#include "constant.h"
#include "help.h"
#include "key_store_helper.h"
#include "password_guard.h"

namespace OHOS {
namespace SignatureTools {
const std::string ParamsRunTool::VERSION = "1.0.0";

PasswordGuard keyPwd;
PasswordGuard keystorePwd;
static std::unordered_map <std::string,
                           std::function<bool(Options* params, SignToolServiceImpl& api)>> DISPATCH_RUN_METHOD {
    {SIGN_ELF, ParamsRunTool::RunSignApp},
    {VERIFY_ELF, ParamsRunTool::RunVerifyApp},
};

bool ParamsRunTool::ProcessCmd(char** args, size_t size)
{
    if (size < CmdUtil::ARGS_MIN_LEN) {
        PrintHelp();
        return true;
    }
    if (args == nullptr || strcmp(args[1], "") == 0) {
        PrintHelp();
        return true;
    } else if (strcmp(args[1], "-h") == 0 || strcmp(args[1], "-help") == 0) {
        PrintHelp();
        return true;
    } else if (strcmp(args[1], "-v") == 0 || strcmp(args[1], "-version") == 0) {
        Version();
        return true;
    } else {
        std::shared_ptr<SignToolServiceImpl> serviceApi = std::make_shared<SignToolServiceImpl>();
        ParamsSharedPtr param = std::make_shared<Params>();
        if (!CmdUtil::Convert2Params(args, size, param)) {
            PrintResult(param->GetMethod() + " failed");
            return false;
        }
        SIGNATURE_TOOLS_LOGD("%s run start time  ", param->GetMethod().c_str());
        if (!DispatchParams(param, *serviceApi)) {
            SIGNATURE_TOOLS_LOGD("%s run end time  ", param->GetMethod().c_str());
            PrintResult(param->GetMethod() + " failed");
            return false;
        }
        SIGNATURE_TOOLS_LOGD("%s run end time  ", param->GetMethod().c_str());
        PrintResult(param->GetMethod() + " success");
    }
    return true;
}

static bool UpdateParamForPwd(Options* options)
{
    std::string keyStoreFile = options->GetString(Options::KEY_STORE_FILE);
    std::string alias = options->GetString(Options::KEY_ALIAS);
    if (!options->Exists(Options::KEY_STORE_RIGHTS)) {
        EVP_PKEY* keyPair = nullptr;
        std::unique_ptr<KeyStoreHelper> keyStoreHelper = std::make_unique<KeyStoreHelper>();
        int status = keyStoreHelper->VerifyKeyStore(keyStoreFile, options->GetChars(Options::KEY_STORE_RIGHTS),
            &keyPair);
        EVP_PKEY_free(keyPair);
        if (status == KEYSTORE_PASSWORD_ERROR) {
            if (!keystorePwd.getPasswordFromUser("Enter keystorePwd (timeout 30 seconds): ")) {
                PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "input pwd error ");
                return false;
            }
            options->emplace(Options::KEY_STORE_RIGHTS, keystorePwd.get());
        } else if (status != RET_OK) {
            return false;
        }
    }

    if (!options->Exists(Options::KEY_RIGHTS)) {
        EVP_PKEY* keyPair = nullptr;
        std::unique_ptr<KeyStoreHelper> keyStoreHelper = std::make_unique<KeyStoreHelper>();
        int status = keyStoreHelper->ReadKeyStore(keyStoreFile, options->GetChars(Options::KEY_STORE_RIGHTS),
            alias, options->GetChars(Options::KEY_RIGHTS), &keyPair);
        EVP_PKEY_free(keyPair);
        if (status == KEY_PASSWORD_ERROR) {
            if (!keyPwd.getPasswordFromUser("Enter keyPwd (timeout 30 seconds): ")) {
                PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "input pwd error ");
                return false;
            }
            options->emplace(Options::KEY_RIGHTS, keyPwd.get());
        } else if (status != RET_OK) {
            return false;
        }
    }
    return true;
}

bool ParamsRunTool::RunSignApp(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::MODE, Options::IN_FILE, Options::OUT_FILE})) {
        return false;
    }
    if (!CmdUtil::UpdateParamForCheckInFile(params, {Options::IN_FILE, Options::APP_CERT_FILE,
                                            Options::PROFILE_FILE, Options::KEY_STORE_FILE, Options::MODULE_FILE,
                                            ParamConstants::PARAM_REMOTE_SIGNERPLUGIN})) {
        return false;
    }
    if (!CmdUtil::UpdateParamForCheckOutFile(params, {Options::OUT_FILE})) {
        return false;
    }
    std::string mode = params->GetString(Options::MODE);
    if (!StringUtils::CaseCompare(mode, LOCAL_SIGN) &&
        !StringUtils::CaseCompare(mode, REMOTE_SIGN)) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "not support command param '" + mode + "'");
        return false;
    }
    if (params->GetString(Options::SELF_SIGN) == ParamConstants::SELF_SIGN_TYPE_1) {
        return api.Sign(params);
    }
    if (StringUtils::CaseCompare(mode, LOCAL_SIGN)) {
        if (!params->Required({Options::KEY_STORE_FILE, Options::KEY_ALIAS, Options::APP_CERT_FILE})) {
            return false;
        }
        if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"})) {
            return false;
        }
    }
    if (!CheckProfile(*params)) {
        return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    if (!UpdateParamForPwd(params)) {
        return false;
    }
    return api.Sign(params);
}

bool ParamsRunTool::CheckProfile(Options& params)
{
    std::string profileFile = params.GetString(Options::PROFILE_FILE);
    std::string profileSigned = params.GetString(Options::PROFILE_SIGNED);
    if (profileFile.empty()) {
        SIGNATURE_TOOLS_LOGI("[SignElf] No profile file");
        return true;
    }
    if (profileSigned == DEFAULT_PROFILE_SIGNED_1) {
        if (!FileUtils::ValidFileType(profileFile, {"p7b"})) {
            return false;
        }
    } else {
        if (!FileUtils::ValidFileType(profileFile, {"json"})) {
            return false;
        }
    }
    return true;
}

bool ParamsRunTool::DispatchParams(const ParamsSharedPtr& params, SignToolServiceImpl& api)
{
    bool isSuccess = false;
    std::string method = params->GetMethod();
    auto it = DISPATCH_RUN_METHOD.find(method);
    if (it == DISPATCH_RUN_METHOD.end()) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "Unsupported method: " + method);
        return false;
    } else {
        isSuccess = it->second(params->GetOptions(), api);
    }
    return isSuccess;
}

void ParamsRunTool::PrintHelp()
{
    PrintMsg(HELP_TXT);
}

void  ParamsRunTool::Version()
{
    PrintMsg(ParamsRunTool::VERSION);
}

bool ParamsRunTool::RunVerifyApp(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::IN_FILE})) {
        return false;
    }
    if (!CmdUtil::UpdateParamForCheckInFile(params, {Options::IN_FILE})) {
        return false;
    }
    return api.Verify(params);
}
} // namespace SignatureTools
} // namespace OHOS