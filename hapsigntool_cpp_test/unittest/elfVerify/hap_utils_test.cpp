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

#include <memory>
#include <fstream>
#include <gtest/gtest.h>

#include "hap_utils.h"
#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {

class HapUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GetAppIdentifier
 * @tc.desc: Test function of HapUtilsTest::GetAppIdentifier() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetAppIdentifier, testing::ext::TestSize.Level1)
{
    std::string content = "{\"type\":\"release\",\"bundle-info\":{\"app-identifier\":\"123\"}}";
    std::string result;
    bool flag = HapUtils::GetAppIdentifier(content, result);

    EXPECT_EQ(flag, true);
    EXPECT_EQ(result, "123");
}

/**
 * @tc.name: GetAppIdentifierDebugType
 * @tc.desc: Test function of HapUtilsTest::GetAppIdentifier() interface for DEBUG profile.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetAppIdentifierDebugType, testing::ext::TestSize.Level1)
{
    std::string content = "{\"type\":\"debug\",\"bundle-info\":{\"app-identifier\":\"123\"}}";
    std::string result;
    bool flag = HapUtils::GetAppIdentifier(content, result);

    EXPECT_EQ(flag, true);
    EXPECT_EQ(result, "DEBUG_LIB_ID");
}

/**
 * @tc.name: GetAppIdentifierUnsupportedType
 * @tc.desc: Test function of HapUtilsTest::GetAppIdentifier() interface for FAILED.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetAppIdentifierUnsupportedType, testing::ext::TestSize.Level1)
{
    std::string content = "{\"type\":\"xxx\",\"bundle-info\":{\"app-identifier\":\"123\"}}";
    std::string result;
    bool flag = HapUtils::GetAppIdentifier(content, result);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: GetAppIdentifierInvalidContent
 * @tc.desc: Test function of HapUtilsTest::GetAppIdentifier() interface for FAILED.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetAppIdentifierInvalidContent, testing::ext::TestSize.Level1)
{
    std::string result;
    EXPECT_EQ(HapUtils::GetAppIdentifier("", result), false);
    EXPECT_EQ(HapUtils::GetAppIdentifier("not json", result), false);
    EXPECT_EQ(HapUtils::GetAppIdentifier("{\"type\":\"release\"}", result), false);
    EXPECT_EQ(HapUtils::GetAppIdentifier("{\"bundle-info\":{\"app-identifier\":\"123\"}}", result), false);
    EXPECT_EQ(HapUtils::GetAppIdentifier(
        "{\"type\":\"release\",\"bundle-info\":{\"app-identifier\":123}}", result), false);
    std::string longId(33, 'a');
    std::string content = "{\"type\":\"release\",\"bundle-info\":{\"app-identifier\":\"" + longId + "\"}}";
    EXPECT_EQ(HapUtils::GetAppIdentifier(content, result), false);
}

/**
 * @tc.name: GetBundleTypeFromJson
 * @tc.desc: Test function of HapUtilsTest::GetBundleTypeFromJson() interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetBundleTypeFromJson, testing::ext::TestSize.Level1)
{
    std::string bundleType;
    // empty module content: not an error, bundleType is empty
    EXPECT_EQ(HapUtils::GetBundleTypeFromJson("", bundleType), true);
    EXPECT_EQ(bundleType, "");

    std::string content = "{\"app\":{\"bundleType\":\"appPlugin\"}}";
    EXPECT_EQ(HapUtils::GetBundleTypeFromJson(content, bundleType), true);
    EXPECT_EQ(bundleType, "appPlugin");

    // no app object: not an error, bundleType is empty
    EXPECT_EQ(HapUtils::GetBundleTypeFromJson("{\"module\":{}}", bundleType), true);
    EXPECT_EQ(bundleType, "");

    // invalid json: parse error
    EXPECT_EQ(HapUtils::GetBundleTypeFromJson("not json", bundleType), false);
    // bundleType is not a string: parse error
    EXPECT_EQ(HapUtils::GetBundleTypeFromJson("{\"app\":{\"bundleType\":123}}", bundleType), false);
}

/**
 * @tc.name: ParsePluginId
 * @tc.desc: Test function of HapUtilsTest::ParsePluginId() interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, ParsePluginId, testing::ext::TestSize.Level1)
{
    std::string pluginId;
    std::string content = "{\"app-services-capabilities\":"
        "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{\"pluginDistributionIDs\":\"plugin-id-123\"}}}";
    EXPECT_EQ(HapUtils::ParsePluginId(content, pluginId), true);
    EXPECT_EQ(pluginId, "plugin-id-123");

    // developer_ID distribution type: no plugin id, not an error
    std::string developerContent = "{\"app-distribution-type\":\"developer_ID\"}";
    EXPECT_EQ(HapUtils::ParsePluginId(developerContent, pluginId), true);
    EXPECT_EQ(pluginId, "");

    // app-services-capabilities not existed
    EXPECT_EQ(HapUtils::ParsePluginId("{\"type\":\"release\"}", pluginId), false);
    // pluginDistributionIDs not existed
    std::string noIdContent = "{\"app-services-capabilities\":"
        "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{}}}";
    EXPECT_EQ(HapUtils::ParsePluginId(noIdContent, pluginId), false);
    // pluginDistributionIDs is not a string
    std::string badTypeContent = "{\"app-services-capabilities\":"
        "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{\"pluginDistributionIDs\":123}}}";
    EXPECT_EQ(HapUtils::ParsePluginId(badTypeContent, pluginId), false);
    // pluginDistributionIDs is empty
    std::string emptyIdContent = "{\"app-services-capabilities\":"
        "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{\"pluginDistributionIDs\":\"\"}}}";
    EXPECT_EQ(HapUtils::ParsePluginId(emptyIdContent, pluginId), false);
    // invalid profile content
    EXPECT_EQ(HapUtils::ParsePluginId("not json", pluginId), false);
}

/**
 * @tc.name: GetHapSigningBlockMagic
 * @tc.desc: Test function of HapUtilsTest::GetHapSigningBlockMagic() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetHapSigningBlockMagic, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> result = HapUtils::GetHapSigningBlockMagic(4);
    int size = result.size();

    EXPECT_NE(size, 0);
}

/**
 * @tc.name: GetHapSigningBlockVersion
 * @tc.desc: Test function of HapUtilsTest::GetHapSigningBlockVersion() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, GetHapSigningBlockVersion, testing::ext::TestSize.Level1)
{
    int result = HapUtils::GetHapSigningBlockVersion(4);

    EXPECT_NE(result, 0);
}

/**
 * @tc.name: ReadFileToByteBuffer
 * @tc.desc: Test function of HapUtilsTest::ReadFileToByteBuffer() interface for FAILED.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HapUtilsTest, ReadFileToByteBuffer, testing::ext::TestSize.Level1)
{
    std::string file;
    ByteBuffer buffer;
    bool result = HapUtils::ReadFileToByteBuffer(file, buffer);

    EXPECT_EQ(result, false);
}
} // namespace SignatureTools
} // namespace OHOS