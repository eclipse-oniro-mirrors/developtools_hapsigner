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

#include "sign_tool_service_impl.h"
#include "pkcs7_data.h"
#include "signature_tools_errno.h"
#include "self_sign_sign_provider.h"
#include "local_sign_provider.h"
#include "signature_tools_log.h"
#include "param_constants.h"
#include "constant.h"
#include "remote_sign_provider.h"
#include "verify_elf.h"

namespace OHOS {
namespace SignatureTools {
bool SignToolServiceImpl::Sign(Options* options)
{
    std::string inFile = options->GetString(Options::IN_FILE);
    if (!FileUtils::isElfFile(inFile)) {
        SIGNATURE_TOOLS_LOGE("inFile is not a elf file");
        return false;
    }
    std::string mode = options->GetString(Options::MODE);
    std::string selfSign = options->GetString(Options::SELF_SIGN);
    std::string skipCodeSign = options->GetString(Options::SKIP_CODE_SIGN);
    std::shared_ptr<SignProvider> signProvider;
    if (ParamConstants::SELF_SIGN_TYPE_1 == selfSign) {
        signProvider = std::make_shared<SelfSignSignProvider>();
    } else if (ParamConstants::SKIP_CODE_SIGN_TRUE == skipCodeSign) {
        // skipCodeSign generates no code signature, no keystore/cert/signAlg is needed.
        // Reuse the keyless provider path; SignElf::Sign writes only .profile/.permission sections.
        signProvider = std::make_shared<SelfSignSignProvider>();
    } else if (LOCAL_SIGN == mode) {
        signProvider = std::make_shared<LocalSignProvider>();
    } else if (REMOTE_SIGN == mode) {
        signProvider = std::make_shared<RemoteSignProvider>();
    } else {
        SIGNATURE_TOOLS_LOGE("Resign mode. But not implemented yet");
        return false;
    }
    return signProvider->SignElf(options);
}

bool SignToolServiceImpl::Verify(Options* option)
{
    VerifyElf verifyElf;
    if (!verifyElf.Verify(option)) {
        return false;
    }
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
