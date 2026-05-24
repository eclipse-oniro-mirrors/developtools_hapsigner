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

#include "hap_resign_test.h"
#include "params_run_tool.h"
#include "local_sign_provider.h"
#include "remote_sign_provider.h"
#include "sign_hap.h"
#include "sign_provider.h"
#include "sign_tool_service_impl.h"
#include "verify_hap.h"
#include "hap_signer_block_utils.h"
#include "param_constants.h"
#include <unistd.h>

namespace OHOS {
namespace SignatureTools {

void HapReSignTest::SetUpTestCase(void)
{
    (void)rename("./hapReSign/phone-default-signed.txt", "./hapReSign/phone-default-signed.hap");
    sync();
}

void HapReSignTest::TearDownTestCase(void)
{
}

/*
 * @tc.name: hap_resign_test_001
 * @tc.desc: This function tests success for interface ReSignHap with localSign mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_test_001, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapReSign/app-release1.pem";
    std::string inFile = "./hapReSign/phone-default-signed.hap";
    std::string keystoreFile = "./hapReSign/ohtest.p12";
    std::string outFile = "./hapReSign/re-phone-default-signed.hap";
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
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_test_002
 * @tc.desc: This function tests failure for interface ReSignHap due to missing required parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_test_002, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "";
    std::string inFile = "./hapReSign/phone-default-signed.hap";
    std::string keystoreFile = "./hapReSign/ohtest.p12";
    std::string outFile = "./hapReSign/re-phone-default-signed.hap";
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
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_test_003
 * @tc.desc: This function tests failure for interface ReSignHap due to invalid input file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_test_003, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string appCertFile = "./hapReSign/app-release1.pem";
    std::string inFile = "./hapReSign/nonexistent.hap";
    std::string keystoreFile = "./hapReSign/ohtest.p12";
    std::string outFile = "./hapReSign/re-phone-default-signed.hap";
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
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_test_004
 * @tc.desc: This function tests failure for interface ReSignHap due to invalid sign algorithm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_test_004, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "invalid";
    std::string appCertFile = "./hapReSign/app-release1.pem";
    std::string inFile = "./hapReSign/phone-default-signed.hap";
    std::string keystoreFile = "./hapReSign/ohtest.p12";
    std::string outFile = "./hapReSign/re-phone-default-signed.hap";
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
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_test_005
 * @tc.desc: This function tests GetResignBlocks interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_test_005, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./hapReSign/phone-default-signed.hap";
    (*params)["inFile"] = inFile;

    bool ret = signProvider->PrepareReSignBlocks(params.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_test_006
 * @tc.desc: This function tests GetResignBlocks with invalid file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_test_006, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./hapSign/entry-default-sign.hap";
    (*params)["inFile"] = inFile;

    bool ret = signProvider->PrepareReSignBlocks(params.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_verify_test_002
 * @tc.desc: This function tests IsVerifyResign interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_verify_test_002, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    SignatureInfo hapSignInfo;

    ByteBuffer blockData("test data", 9);
    OptionalBlock codeReSignBlock = {HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID, blockData};
    hapSignInfo.optionBlocks.push_back(codeReSignBlock);

    bool ret = verify.IsVerifyResign(hapSignInfo);
    EXPECT_EQ(ret, true);

    hapSignInfo.optionBlocks.clear();
    OptionalBlock profileBlock = {HapUtils::HAP_PROFILE_BLOCK_ID, blockData};
    hapSignInfo.optionBlocks.push_back(profileBlock);

    ret = verify.IsVerifyResign(hapSignInfo);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_verify_test_003
 * @tc.desc: This function tests CheckFileNameAndBlockArray interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_verify_test_003, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    std::string hapFilePath = "test.hap";
    ByteBuffer propertyBlockArray("test data for property block", 30);

    bool ret = verify.CheckFileNameAndBlockArray(hapFilePath, propertyBlockArray);
    EXPECT_EQ(ret, true);

    std::string invalidPath = "test";
    ret = verify.CheckFileNameAndBlockArray(invalidPath, propertyBlockArray);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_resign_verify_test_004
 * @tc.desc: This function tests outputReSignOptionalBlocks interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_verify_test_004, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    std::string outputHapSignFile = "./hapReSign/outputHapSign.bin";
    std::string outputCodeResignFile = "./hapReSign/outputCodeResign.bin";

    ByteBuffer bf1("profile data", 12);
    ByteBuffer bf2("property data", 14);
    ByteBuffer bf3("proof data", 10);
    ByteBuffer bf4("hap sign data", 13);
    ByteBuffer bf5("code resign data", 16);

    std::vector<OptionalBlock> optionBlocks;
    optionBlocks.push_back({HapUtils::HAP_PROFILE_BLOCK_ID, bf1});
    optionBlocks.push_back({HapUtils::HAP_PROPERTY_BLOCK_ID, bf2});
    optionBlocks.push_back({HapUtils::HAP_PROOF_OF_ROTATION_BLOCK_ID, bf3});
    optionBlocks.push_back({HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID, bf4});
    optionBlocks.push_back({HapUtils::ENTERPRISE_CODE_RE_SIGN_BLOCK_ID, bf5});

    bool ret = verify.outputReSignOptionalBlocks(outputHapSignFile, outputCodeResignFile, optionBlocks);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_resign_verify_test_005
 * @tc.desc: This function tests outputReSignOptionalBlocks with invalid block type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapReSignTest, hap_resign_verify_test_005, testing::ext::TestSize.Level1)
{
    VerifyHap verify;
    std::string outputHapSignFile = "./hapReSign/outputHapSign.bin";
    std::string outputCodeResignFile = "./hapReSign/outputCodeResign.bin";

    ByteBuffer bf1("invalid block data", 18);
    std::vector<OptionalBlock> optionBlocks;
    optionBlocks.push_back({0x99999999, bf1});

    bool ret = verify.outputReSignOptionalBlocks(outputHapSignFile, outputCodeResignFile, optionBlocks);
    EXPECT_EQ(ret, false);
}

} // namespace SignatureTools
} // namespace OHOS