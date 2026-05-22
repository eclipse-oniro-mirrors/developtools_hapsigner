/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <unistd.h>

#include "sign_tool_service_impl.h"
#include "options.h"
#include "sign_provider.h"
#include "local_sign_provider.h"
#include "remote_sign_provider.h"
#include "verify_hap.h"
#include "hap_signer_block_utils.h"
#include "param_constants.h"

namespace OHOS {
namespace SignatureTools {

void GenReSignFuzzHap(const std::string& path)
{
    std::ofstream outfile(path);
    if (!outfile) {
        SIGNATURE_TOOLS_LOGE("Unable to open file: %s", path.c_str());
        return;
    }
    outfile << "Hello, this is a test HAP for resign fuzz.\n";
    outfile.flush();
    outfile.close();
    return;
}

bool HapReSignFuzzTest001(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest002(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias(reinterpret_cast<const char*>(data), size);
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest003(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg(reinterpret_cast<const char*>(data), size);
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest004(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile(reinterpret_cast<const char*>(data), size);
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest005(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile(reinterpret_cast<const char*>(data), size);
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest006(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile(reinterpret_cast<const char*>(data), size);
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest007(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile(reinterpret_cast<const char*>(data), size);
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest008(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode(reinterpret_cast<const char*>(data), size);
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

bool HapReSignFuzzTest009(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./hapReSign/test-signed.hap";
    (*params)["inFile"] = inFile;

    bool ret = signProvider->PrepareReSignBlocks(params.get());
    return ret;
}

bool HapReSignFuzzTest010(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile(reinterpret_cast<const char*>(data), size);
    (*params)["inFile"] = inFile;

    bool ret = signProvider->PrepareReSignBlocks(params.get());
    return ret;
}

bool HapReSignFuzzTest011(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    VerifyHap verify;
    SignatureInfo hapSignInfo;

    int blockType = static_cast<int>(data[0]) % 10;
    ByteBuffer blockData(reinterpret_cast<const char*>(data + 1), size - 1);
    OptionalBlock testBlock = {blockType, blockData};
    hapSignInfo.optionBlocks.push_back(testBlock);

    bool ret = verify.IsVerifyResign(hapSignInfo);
    return ret;
}

bool HapReSignFuzzTest012(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    VerifyHap verify;
    std::string hapFilePath(reinterpret_cast<const char*>(data), size);
    size_t propertyBlockArraySize = 9;
    ByteBuffer propertyBlockArray("test data", propertyBlockArraySize);

    bool ret = verify.CheckFileNameAndBlockArray(hapFilePath, propertyBlockArray);
    return ret;
}

bool HapReSignFuzzTest013(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    VerifyHap verify;
    std::string outputHapSignFile = "./hapReSign/outputHapSign-fuzz.bin";
    std::string outputCodeResignFile = "./hapReSign/outputCodeResign-fuzz.bin";
    size_t maxOptionalBlocks = 10;

    std::vector<OptionalBlock> optionBlocks;
    for (size_t i = 0; i < size && i < maxOptionalBlocks; i++) {
        int blockType = static_cast<int>(data[i]);
        ByteBuffer blockData(reinterpret_cast<const char*>(data + i + 1), size - i - 1);
        OptionalBlock testBlock = {blockType, blockData};
        optionBlocks.push_back(testBlock);
    }

    bool ret = verify.outputReSignOptionalBlocks(outputHapSignFile, outputCodeResignFile, optionBlocks);
    return ret;
}

bool HapReSignFuzzTest014(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<RemoteSignProvider> signProvider = std::make_unique<RemoteSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "remoteSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string inFile = "./hapReSign/test-signed.hap";
    std::string outFile = "./hapReSign/test-resigned-fuzz.hap";
    std::string onlineAuthMode = "account";
    std::string compatibleVersion = "8";
    std::string signerPlugin(reinterpret_cast<const char*>(data), size);
    std::string signServer = "./hapSign/app-release1.pem";
    std::string username = "test";
    char userPwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["appCertFile"] = appCertFile;
    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;
    (*params)["onlineAuthMode"] = onlineAuthMode;
    (*params)["compatibleVersion"] = compatibleVersion;
    (*params)["signerPlugin"] = signerPlugin;
    (*params)["signServer"] = signServer;
    (*params)["username"] = username;
    (*params)["userPwd"] = userPwd;

    bool ret = signProvider->ReSignHap(params.get());
    return ret;
}

} // namespace SignatureTools
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SignatureTools::GenReSignFuzzHap("./hapReSign/test-signed.hap");
    sync();
    /* Run your code on data */
    OHOS::SignatureTools::HapReSignFuzzTest001(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest002(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest003(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest004(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest005(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest006(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest007(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest008(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest009(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest010(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest011(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest012(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest013(data, size);
    OHOS::SignatureTools::HapReSignFuzzTest014(data, size);
    return 0;
}