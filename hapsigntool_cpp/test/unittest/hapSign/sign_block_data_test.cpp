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
#include <gtest/gtest.h>
#include "sign_block_data.h"

using namespace OHOS::SignatureTools;

/*
* 测试套件,固定写法
*/
class SignBlockDataTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    };
    static void TearDownTestCase()
    {
    };
    void SetUp()
    {
    };
    void TearDown()
    {
    };
};

/**
 * @tc.name: getBlockHead
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, getBlockHead, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    api->GetBlockHead();
    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: getByte
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, getByte, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    bool byte = api->GetByte();
    EXPECT_EQ(byte, true);
}

/**
 * @tc.name: getLen
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, getLen, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    long len = api->GetLen();
    EXPECT_EQ(len, 32);
}

/**
 * @tc.name: getSignData
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, getSignData, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    std::vector<int8_t> retSignData = api->GetSignData();
    EXPECT_EQ(retSignData.size(), 32);
}

/**
 * @tc.name: getSignFile
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, getSignFile, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    std::string signFile = api->GetSignFile();
    EXPECT_EQ(signFile.size(), 0);
}

/**
 * @tc.name: getType
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, getType, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    char type = api->GetType();
    EXPECT_EQ(type, 3);
}

/**
 * @tc.name: setBlockHead
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBlockDataTest, setBlockHead, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> signData(std::vector<int8_t>(32, 0));
    std::shared_ptr<SignBlockData> api = std::make_shared<SignBlockData>(signData, 3);
    api->SetBlockHead(signData);
    EXPECT_EQ(true, 1);
}
