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
#include <chrono>
#include <thread>
#include <string>

#include "gtest/gtest.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "nlohmann/json.hpp"
#include "signer_factory.h"
#include "profile_sign_tool.h"
#include "params_run_tool.h"
#include "pkcs7_data.h"
#include "signer_config.h"
#include "local_signer.h"
#include "bc_pkcs7_generator.h"
#include "bc_signeddata_generator.h"
#include "profile_verify.h"
#include "constant.h"
#include "profile_verify_utils.h"
#include "cms_utils.h"

using  nlohmann::json;

namespace OHOS {
namespace SignatureTools {

// sign profile使用的全局参数
static const std::string SIGN_PROFILE_MODE = "localSign";
static const std::string SIGN_PROFILE_KEY_ALIAS = "oh-profile1-key-v1";
static const std::string SIGN_PROFILE_PROFILE_CERT_FILE = "./signProfile/profile-release1.pem";
static const std::string SIGN_PROFILE_SIGN_ALG = "SHA384withECDSA";
static const std::string SIGN_PROFILE_KEY_STORE_FILE = "./signProfile/ohtest.p12";
static const std::string SIGN_PROFILE_OUT_FILE = "./signProfile/signed-profile.p7b";
static const std::string SIGN_PROFILE_IN_FILE = "./signProfile/profile.json";

static const std::string SIGN_PROFILE_CERT_PEM = "./signProfile/profile-release1-cert.pem";
static const std::string SIGN_PROFILE_REVERSE_PEM = "./signProfile/profile-release1-reverse.pem";
static const std::string SIGN_PROFILE_DOUBLE_CERT_PEM = "./signProfile/profile-release1-invalid_cert_chain.pem";

//verify profile 使用的全局参数
static const std::string VERIFY_PROFILE_IN_FILE = "./signProfile/app1-profile1.p7b";
static const std::string VERIFY_PROFILE_OUT_FILE = "./signProfile/VerifyResult.json";
//sign app 使用全局参数
static const std::string SIGN_APP_MODE = "localSign";
static const std::string SIGN_APP_KEY_ALIAS = "oh-app1-key-v1";
static const std::string SIGN_APP_APP_CERT_FILE = "./signProfile/app-release1.pem";
static const std::string SIGN_APP_PROFILE_FILE = "./signProfile/app1-profile1.p7b";
static const std::string SIGN_APP_IN_FILE = "./signProfile/app1-unsigned.hap";
static const std::string SIGN_APP_SIGN_ALG = "SHA256withECDSA";
static const std::string SIGN_APP_KEY_STORE_FILE = "./signProfile/ohtest.p12";
static const std::string SIGN_APP_OUT_FILE = "./signProfile/app1-signed.hap";
//verify app 使用全局参数
static const std::string VERIFY_APP_CERT_FILE = "./signProfile/app-release1.pem";
static const std::string VERIFY_APP_PROFILE_FILE = "./signProfile/app1-profile1.p7b";
static const std::string VERIFY_APP_IN_FILE = "./signProfile/app1-signed.hap";

class ProfileTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp()override;
    void TearDown()override;
};
void ProfileTest::SetUpTestCase(void)
{
}

void ProfileTest::TearDownTestCase(void)
{
}

void ProfileTest::SetUp()
{
}

void ProfileTest::TearDown()
{
}

/**
 * @tc.name: profile_test001
 * @tc.desc: Test function of ParseProfile() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test001, testing::ext::TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context;
    Pkcs7Context hapPkcs7Context;
    int length = 5;
    std::string profile = "hello,world";
    ByteBuffer pkcs7ProfileBlock;
    pkcs7ProfileBlock.SetCapacity(length);
    pkcs7ProfileBlock.PutData("hello", length);
    int result = ProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: profile_test002
 * @tc.desc: Test function of ProfileVerifyUtils::VerifyProfile() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test002, testing::ext::TestSize.Level1)
{
    Pkcs7Context p7context;
    int result = ProfileVerifyUtils::VerifyProfile(p7context);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: profile_test003
 * @tc.desc: Test function of ProfileVerifyUtils::VerifyProfile() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test003, testing::ext::TestSize.Level1)
{
    Pkcs7Context p7context;
    X509* cert = X509_new();
    std::vector<X509*> certChain;
    certChain.push_back(cert);
    p7context.certChains.push_back(certChain);
    int result = ProfileVerifyUtils::VerifyProfile(p7context);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: profile_test004
 * @tc.desc: Test function of Pkcs7Generator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test004, testing::ext::TestSize.Level1)
{
    std::string content;
    SignerConfig* config = NULL;
    std::string ret;
    std::shared_ptr<Pkcs7Generator> generator = std::make_shared<BCPkcs7Generator>();
    int result = generator->GenerateSignedData(content, config, ret);
    EXPECT_TRUE(result <= 0);
}

/**
 * @tc.name: profile_test005
 * @tc.desc: Test function of Pkcs7Generator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test005, testing::ext::TestSize.Level1)
{
    std::string content = "hello,world";
    SignerConfig* config = NULL;
    std::string ret;
    std::shared_ptr<Pkcs7Generator> generator = std::make_shared<BCPkcs7Generator>();
    int result = generator->GenerateSignedData(content, config, ret);
    EXPECT_TRUE(result <= 0);
}

/**
 * @tc.name: profile_test006
 * @tc.desc: Test function of Pkcs7Generator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test006, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_APP_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_APP_APP_CERT_FILE;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = "";
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA256;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    int result = pkcs7Generator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test007
 * @tc.desc: Test function of Pkcs7Generator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test007, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_APP_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_APP_APP_CERT_FILE;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::DSA_WITH_SHA512;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    int result = pkcs7Generator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test008
 * @tc.desc: Test function of Pkcs7Generator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test008, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_PROFILE_DOUBLE_CERT_PEM;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA256;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    int result = pkcs7Generator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test009
 * @tc.desc: Test function of SignedDataGenerator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test009, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_APP_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_APP_APP_CERT_FILE;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_APP_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA512;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<BCSignedDataGenerator> signedDataGenerator =
        std::make_shared<BCSignedDataGenerator>();
    signedDataGenerator->SetOwnerId(OWNERID_OID);
    int result = signedDataGenerator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test010
 * @tc.desc: Test function of SignedDataGenerator::GenerateSignedData() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test010, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_PROFILE_DOUBLE_CERT_PEM;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA256;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<BCSignedDataGenerator> signedDataGenerator =
        std::make_shared<BCSignedDataGenerator>();
    signedDataGenerator->SetOwnerId("ownerID str");
    int result = signedDataGenerator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test011
 * @tc.desc: Test function of Pkcs7Data::Verify() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test011, testing::ext::TestSize.Level1)
{
    std::string content = "signed content data";
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    PKCS7Data p7;
    std::string p7b;
    PKCS7* pkcs7 = NULL;
    int result = p7.Sign(content, signer, "SHA384withECDSA", p7b);
    EXPECT_EQ(result, 0);
    const unsigned char* p = reinterpret_cast<const unsigned char*>(p7b.data());
    pkcs7 = d2i_PKCS7(NULL, &p, static_cast<long>(p7b.size()));
    STACK_OF(X509)* certs = pkcs7->d.sign->cert;
    int num = 1;
    while (sk_X509_num(certs) > num) {
        X509* cert = sk_X509_delete(certs, sk_X509_num(certs) - 1);
        X509_free(cert);
    }
    sk_X509_push(certs, sk_X509_value(certs, 0));
    X509_up_ref(sk_X509_value(certs, 0));
    unsigned char* out = NULL;
    int len = 0;
    len = i2d_PKCS7(pkcs7, &out);
    p7b.assign(out, out + len);
    result = p7.Parse(p7b);
    EXPECT_EQ(result, 0);
    result = p7.Verify();
    PKCS7_free(pkcs7);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test013
 * @tc.desc: Test function of Pkcs7Data::Verify() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test013, testing::ext::TestSize.Level1)
{
    std::string content = "signed content data";
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    PKCS7Data p7;
    std::string p7b;
    PKCS7* pkcs7 = NULL;
    int result = p7.Sign(content, signer, "SHA384withECDSA", p7b);
    EXPECT_EQ(result, 0);
    const unsigned char* p = reinterpret_cast<const unsigned char*>(p7b.data());
    pkcs7 = d2i_PKCS7(NULL, &p, static_cast<long>(p7b.size()));
    STACK_OF(X509)* certs = pkcs7->d.sign->cert;
    sk_X509_delete(certs, 2);
    unsigned char* out = NULL;
    int len = 0;
    len = i2d_PKCS7(pkcs7, &out);
    p7b.assign(out, out + len);
    result = p7.Parse(p7b);
    EXPECT_EQ(result, 0);
    result = p7.Verify();
    PKCS7_free(pkcs7);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test014
 * @tc.desc: Test function of Pkcs7Data::Verify() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test014, testing::ext::TestSize.Level1)
{
    std::string content = "signed content data";
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    PKCS7Data p7;
    std::string p7b;
    PKCS7* pkcs7 = NULL;
    int result = p7.Sign(content, signer, "SHA384withECDSA", p7b);
    EXPECT_EQ(result, 0);
    const unsigned char* p = reinterpret_cast<const unsigned char*>(p7b.data());
    pkcs7 = d2i_PKCS7(NULL, &p, static_cast<long>(p7b.size()));
    STACK_OF(X509)* certs = pkcs7->d.sign->cert;
    sk_X509_delete(certs, 2);
    sk_X509_push(certs, sk_X509_value(certs, 1));
    X509_up_ref(sk_X509_value(certs, 1));
    PKCS7Data::PrintCertChainSub(certs);
    unsigned char* out = NULL;
    int len = 0;
    len = i2d_PKCS7(pkcs7, &out);
    p7b.assign(out, out + len);
    result = p7.Parse(p7b);
    PKCS7Data::PrintCertChainSub(certs);
    EXPECT_EQ(result, 0);
    result = p7.Verify();
    PKCS7_free(pkcs7);
    EXPECT_TRUE(result < 0);
}

/**
 * @tc.name: profile_test015
 * @tc.desc: Test function of Provision operator ==() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test015, testing::ext::TestSize.Level1)
{
    ProfileInfo* info = NULL;
    ProfileInfo info2;
    info = &info2;
    info2 = *info;
}

/**
 * @tc.name: profile_test016
 * @tc.desc: Test function of CmsUtils::VerifySignDataWithUnsignedDataDigest() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test016, testing::ext::TestSize.Level1)
{
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::GenerateP7b(adapter, content, ret);
    EXPECT_EQ(result, 0);
    std::vector<int8_t> signedData(ret.begin(), ret.end());
    std::string data = "hello,world";
    std::vector<int8_t> unsignedData(data.begin(), data.end());
    EXPECT_EQ(CmsUtils::VerifySignDataWithUnsignedDataDigest(unsignedData, signedData), false);
}

/**
 * @tc.name: profile_test017
 * @tc.desc: Test function of PKCS7Data::SortX509Stack() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, test069, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs = sk_X509_new(NULL);
    PKCS7Data::SortX509Stack(certs);
    sk_X509_free(certs);
}

/**
 * @tc.name: profile_test017
 * @tc.desc: Test function of PKCS7Data::SortX509Stack() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, test070, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs_ = NULL;
    STACK_OF(X509)* certs = sk_X509_new(NULL);
    PKCS7Data::SortX509Stack(certs_);
    sk_X509_free(certs);
}

/**
 * @tc.name: profile_test018
 * @tc.desc: Test function of PKCS7Data::ReverseX509Stack() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test018, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs = NULL;
    PKCS7Data::ReverseX509Stack(certs);
}

/**
 * @tc.name: profile_test019
 * @tc.desc: Test function of PKCS7Data::PrintCertChainSub() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test019, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs = NULL;
    PKCS7Data::PrintCertChainSub(certs);
}

/**
 * @tc.name: profile_test020
 * @tc.desc: Test function of PKCS7Data::GetASN1Time() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test020, testing::ext::TestSize.Level1)
{
    ASN1_TIME* time = NULL;
    std::string result = PKCS7Data::GetASN1Time(time);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: profile_test021
 * @tc.desc: Test function of PKCS7Data::SortX509Stack() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test021, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs = NULL;
    PKCS7Data::SortX509Stack(certs);
}

/**
 * @tc.name: profile_test022
 * @tc.desc: Test function of ParseProfile() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test022, testing::ext::TestSize.Level1)
{
    std::string  provision = "{\"bundle-info\":{\"app-feature\":\"hos_system_app\",\"bundle-n"
        "ame\":\"com.OpenHarmony.app.test\",\"developer-id\":\"OpenHarmony\",\"development-certi"
        "ficate\":\"-----BEGIN CERTIFICATE-----\\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\\n"
        "-----END CERTIFICATE-----\\n"
        "\"},\"debug-info\":{\"device-id-type\":\"udid\",\"device-ids\":[\"69C7505BE341BDA594"
        "8C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42\",\"7EED06506FCE6325EB2E2FAA019458B856"
        "AB10493A6718C7679A73F958732865\"]},\"issuer\":\"pki_internal\",\"permissions\":{\"rest"
        "ricted-permissions\":[\"\"]},\"type\":\"debug\",\"uuid\":\"fe686e1b-3770-4824-a938-961"
        "b140a7c98\",\"validity\":{\"not-after\":1705127532,\"not-before\":\"1610519532\"},\"ve"
        "rsion-code\":1,\"version-name\":\"1.0.0\"}";
    ProfileInfo info;
    AppProvisionVerifyResult result = ParseProfile(provision, info);
    EXPECT_EQ(result, AppProvisionVerifyResult::PROVISION_OK);
}

/**
 * @tc.name: profile_test023
 * @tc.desc: Test function of ParseProfile() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test023, testing::ext::TestSize.Level1)
{
    std::string  provision = "{\"bundle-info\":{\"app-feature\":\"hos_system_app\",\"bundle-nam"
        "e\":\"com.OpenHarmony.app.test\",\"developer-id\":\"OpenHarmony\",\"development-certi"
        "ficate\":\"-----BEGIN CERTIFICATE-----\\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\\n"
        "-----END CERTIFICATE-----\\n"
        "\"},\"debug-info\":{\"device-id-type\":\"udid\",\"device-ids\":[\"69C7505BE341BDA5948C"
        "3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42\",\"7EED06506FCE6325EB2E2FAA019458B856AB1"
        "0493A6718C7679A73F958732865\"]},\"issuer\":\"pki_internal\",\"permissions\":{\"restric"
        "ted-permissions\":[\"\"]},\"type\":\"debug\",\"uuid\":\"fe686e1b-3770-4824-a938-961b14"
        "0a7c98\",\"validity\":{\"name\":\"weixing\"},\"version-code\":1,\"version-name\":\"1.0.0\"}";
    ProfileInfo info;
    AppProvisionVerifyResult result = ParseProfile(provision, info);
    EXPECT_EQ(result, AppProvisionVerifyResult::PROVISION_OK);
}

/**
 * @tc.name: profile_test024
 * @tc.desc: Test function of ParseProvision() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test024, testing::ext::TestSize.Level1)
{
    std::string  provision = "{\"app-distribution-type\": \"app_gallery\",\"bundle-info\":{\"app-"
        "feature\":\"hos_system_app\",\"bundle-name\":\"com.OpenHarmony.app.test\",\"developer-id\":\"O"
        "penHarmony\",\"distribution-certificate\":\"-----BEGIN CERTIFICATE-----\\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\\n"
        "-----END CERTIFICATE-----\\n"
        "\"},\"debug-info\":{\"device-id-type\":\"udid\",\"device-ids\":[\"69C7505BE341BDA5948C3C0CB"
        "44ABCD530296054159EFE0BD16A16CD0129CC42\",\"7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C76"
        "79A73F958732865\"]},\"issuer\":\"pki_internal\",\"permissions\":{\"restricted-permissions\":"
        "[\"\"]},\"type\":\"release\",\"uuid\":\"fe686e1b-3770-4824-a938-961b140a7c98\",\"validity\":"
        "{\"not-after\":1705127532,\"not-before\":1610519532},\"version-code\":1,\"version-name\":\"1.0.0\"}";
    ProfileInfo info;
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_EQ(result, AppProvisionVerifyResult::PROVISION_OK);
}

/**
 * @tc.name: profile_test025
 * @tc.desc: Test function of PKCS7Data::ReverseX509Stack() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test025, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs_ = NULL;
    STACK_OF(X509)* certs = sk_X509_new(NULL);
    PKCS7Data::ReverseX509Stack(certs_);
    sk_X509_free(certs);
}

/**
 * @tc.name: profile_test026
 * @tc.desc: Test function of PKCS7Data::ReverseX509Stack() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test026, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs = sk_X509_new(NULL);
    PKCS7Data::ReverseX509Stack(certs);
    sk_X509_free(certs);
}

/**
 * @tc.name: profile_test027
 * @tc.desc: Test function of ParseProvision() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test027, testing::ext::TestSize.Level1)
{
    std::string  provision = "{\"app-distribution-type\": \"app_gallery\","
        "\"bundle-info\":{\"app-feature\":\"hos_system_app\",\"bundle-name\":"
        "\"com.OpenHarmony.app.test\",\"developer-id\":\"OpenHarmony\","
        "\"distribution-certificate\":\"-----BEGIN CERTIFICATE-----\\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\\n"
        "-----END CERTIFICATE-----\\n"
        "\"},\"debug-info\":{\"device-id-type\":\"udid\",\"device-ids\":["
        "\"69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42\","
        "\"7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865\"]},"
        "\"issuer\":\"pki_internal\",\"permissions\":{\"restricted-permissions"
        "\":[\"\"]},\"type\":\"release\",\"uuid\":\"\",\"validity\":{\"not-after"
        "\":1705127532,\"not-before\":1610519532},\"version-code\":1,\"version-name\":\"1.0.0\"}";
    ProfileInfo info;
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_EQ(result, AppProvisionVerifyResult::PROVISION_INVALID);
}

/**
 * @tc.name: profile_test028
 * @tc.desc: Test function of ParseProvision() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ProfileTest, profile_test028, testing::ext::TestSize.Level1)
{
    std::string  provision = "{\"app-distribution-type\": \"app_gallery\","
        "\"bundle-info\":{\"app-feature\":\"hos_system_app\",\"bundle-name\":"
        "\"com.OpenHarmony.app.test\",\"developer-id\":\"OpenHarmony\","
        "\"distribution-certificate\":\"-----BEGIN CERTIFICATE-----\\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\\n"
        "-----END CERTIFICATE-----\\n"
        "\"},\"debug-info\":{\"device-id-type\":\"udid\",\"device-ids\":["
        "\"69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42\","
        "\"7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865\"]},"
        "\"issuer\":\"pki_internal\",\"permissions\":{\"restricted-permissions"
        "\":[\"\"]},\"type\":\"release\",\"uuid\":\"\",\"validity\":{\"not-after"
        "\":1705127532,\"not-before\":1610519532},\"version-code\":1,\"version-name\":\"1.0.0\"}";
    ProfileInfo info;
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_EQ(result, AppProvisionVerifyResult::PROVISION_INVALID);
}

}
}
