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

#include <gtest/gtest.h>
#include "hap_utils.h"

namespace OHOS {
namespace SignatureTools {

/**
 * Unit tests for HapUtils::GetSkillNamesFromJson.
 *
 * Covers the four scenarios required by spec.md AC-1/AC-2/AC-4:
 *  - TC-C-1: normal skillProfiles array
 *  - TC-C-2: empty skillProfiles array
 *  - TC-C-3: module.json without skillProfiles field
 *  - TC-C-4: invalid JSON
 *  - TC-C-5: malformed name field type is skipped, valid entries preserved
 */
class HapUtilsSkillTest : public testing::Test {};

// TC-C-1 normal
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_Normal_ReturnsAllNames)
{
    std::string json = R"({"module":{"skillProfiles":[{"name":"MySkill1"},{"name":"MySkill2"}]}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "MySkill1");
    EXPECT_EQ(result[1], "MySkill2");
}

// TC-C-2 empty array
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_EmptyArray_ReturnsEmpty)
{
    std::string json = R"({"module":{"skillProfiles":[]}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_TRUE(result.empty());
}

// TC-C-3 missing field
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_NoSkillProfiles_ReturnsEmpty)
{
    std::string json = R"({"module":{}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_TRUE(result.empty());
}

// TC-C-4 invalid JSON
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_InvalidJson_ReturnsEmpty)
{
    std::string json = "not a valid json";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_TRUE(result.empty());
}

// TC-C-5 malformed name field type is skipped, valid entries preserved
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_MalformedNameType_SkipsAndPreservesValid)
{
    std::string json = R"({"module":{"skillProfiles":[)"
        R"({"name":123},)"
        R"({"name":true},)"
        R"({"name":"ValidSkill"},)"
        R"({"name":""})"
        R"]}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "ValidSkill");
}

}  // namespace SignatureTools
}  // namespace OHOS
