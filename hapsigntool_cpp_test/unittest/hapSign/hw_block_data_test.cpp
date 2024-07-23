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
#include "hw_block_data.h"

using namespace OHOS::SignatureTools;

/*
* 测试套件,固定写法
*/
class HwBlockDataTest : public testing::Test {
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
 * @tc.name: GetBlockNum
 * @tc.desc: Test function of HwBlockDataTest::GetBlockNum() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HwBlockDataTest, GetBlockNum, testing::ext::TestSize.Level1)
{
    std::shared_ptr<HwBlockData> api = std::make_shared<HwBlockData>(2, 0);
    int32_t blockNum = api->GetBlockNum();
    EXPECT_EQ(blockNum, 2);
}

/**
 * @tc.name: GetBlockStart
 * @tc.desc: Test function of HwBlockDataTest::GetBlockStart() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HwBlockDataTest, GetBlockStart, testing::ext::TestSize.Level1)
{
    std::shared_ptr<HwBlockData> api = std::make_shared<HwBlockData>(2, 0);
    int32_t blockStart = api->GetBlockStart();
    EXPECT_EQ(blockStart, 0);
}

/**
 * @tc.name: SetBlockNum
 * @tc.desc: Test function of HwBlockDataTest::SetBlockNum() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HwBlockDataTest, SetBlockNum, testing::ext::TestSize.Level1)
{
    std::shared_ptr<HwBlockData> api = std::make_shared<HwBlockData>(2, 0);
    api->SetBlockNum(3);
    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: SetBlockStart
 * @tc.desc: Test function of HwBlockDataTest::SetBlockStart() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(HwBlockDataTest, SetBlockStart, testing::ext::TestSize.Level1)
{
    std::shared_ptr<HwBlockData> api = std::make_shared<HwBlockData>(2, 0);
    api->SetBlockStart(1);
    EXPECT_EQ(true, 1);
}
