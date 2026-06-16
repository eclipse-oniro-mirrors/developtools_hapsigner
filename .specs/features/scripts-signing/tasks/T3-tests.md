# T3: 新增双端单元测试 + Python E2E 测试

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | T3 |
| 标题 | 新增双端单元测试（Java + C++）+ Python 端到端 E2E 测试 |
| 关联 Feature | FEAT-20260603-001 |
| 目标仓库 | `developtools/hapsigner` |
| 目标模块 | `hapsigntool_cpp_test/unittest/codeSigning/utils/` + `hapsigntool/hap_sign_tool_lib/src/test/java/com/ohos/hapsigntool/codesigning/utils/` + `tools/test/` |
| 分支 | `dev` |
| 优先级 | P2 |
| 复杂度 | 中 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

**Java 端：新增 `HapUtilsTest.java`**

1. 在 `hapsigntool/hap_sign_tool_lib/src/test/java/com/ohos/hapsigntool/codesigning/utils/` 下新建 `HapUtilsTest.java`
2. 覆盖 `HapUtils.getSkillNamesFromJson(JarFile)` 至少 4 个场景：
   - **TC-J-1 正常**：module.json 含 `skillProfiles` 数组，每个对象有 `name` 字段 → 返回 name 列表
   - **TC-J-2 空数组**：`skillProfiles` = `[]` → 返回空 list
   - **TC-J-3 缺字段**：module.json 无 `skillProfiles` 字段 → 返回空 list
   - **TC-J-4 非法 JSON**：module.json 内容损坏 → 返回空 list（不抛异常）
3. 每个 TC 用 `assertEquals` 验证返回值，使用临时 JarFile（test resources 目录）
4. `mvn test` 在 `hapsigntool/` 目录执行，验证全部 TC 通过

**C++ 端：新增 `hap_utils_skill_test.cpp`**

1. 在 `hapsigntool_cpp_test/unittest/codeSigning/utils/` 下新建 `hap_utils_skill_test.cpp`
2. 覆盖 `HapUtils::GetSkillNamesFromJson(const std::string& moduleJson)` 至少 4 个场景：
   - **TC-C-1 正常**：moduleJson 含 `skillProfiles` 数组 → 返回 name 列表
   - **TC-C-2 空数组**：`skillProfiles` = `[]` → 返回空 vector
   - **TC-C-3 缺字段**：moduleJson 无 `skillProfiles` 字段 → 返回空 vector
   - **TC-C-4 非法 JSON**：moduleJson 损坏 → 返回空 vector（不 crash）
3. 复用仓内 gtest 框架（参考 `cms_utils_test.cpp` / `fs_digest_utils_test.cpp`）
4. **测试源码合入仓内，但仓内不构建**（`gn gen && ninja` 在本仓内无法跑通）
5. 用户手动构建并运行后确认 gtest 通过

**Python 端：新增 E2E 测试 `scripts_signing_e2e.py`**

1. 在 `tools/test/scripts_signing_e2e.py` 下新建 E2E 脚本
2. 程序化生成 9 个不同配置的 HAP 包，覆盖所有 6 条 AC
3. 对每个 HAP 调用 `hap-sign-tool.jar sign-app` 签名
4. 对签名结果调用 `hap-sign-tool.jar verify-app` 验证
5. 仅检查 exit code（user 决策：不做严格 fileNameList 验证）
6. 9 个 TC：
   - **TC-E-1, TC-E-2** → AC-1
   - **TC-E-3** → AC-3（目录项跳过）
   - **TC-E-4** → AC-5（嵌套子目录不签 — 验证 F9/F10 修复）
   - **TC-E-5, TC-E-6** → AC-2
   - **TC-E-7** → AC-4（损坏 module.json → 抛异常 sign rc=1）
   - **TC-E-8** → AC-4（缺 module.json → warn-and-continue sign rc=0）
   - **TC-E-9** → AC-1 + AC-3 混合

### 不做什么

- 不修改现有 `code_signing_test.cpp` / `HapSignToolTest`
- 不在 C++ 端新增 BUILD.gn 单元测试 target
- 不生成 Java/C++ 二进制等价性集成测试
- 不修改 `CodeSigning::SignSkillScripts` / `CodeSigning.signSkillScripts` 的逻辑
- 不做严格 fileNameList 验证（仅 exit code 验证）

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-1 | spec.md | TC-J-1 / TC-C-1：正常 skillProfiles 解析 |
| AC-2 | spec.md | TC-J-3 / TC-C-3：缺字段时返回空 list（向后兼容） |
| AC-3 | spec.md | 已有 `CheckFileNameForScripts` 逻辑覆盖（不直接测；通过 TC-J-1 / TC-C-1 间接验证 entry name 格式） |
| AC-4 | spec.md | TC-J-4 / TC-C-4：非法 JSON 不抛异常；TC-J-3 / TC-C-3 缺字段不抛异常 |
| AC-5 | spec.md | 嵌套子目录不签名（路径前缀 `startsWith` 行为；C++ 端 `GetScriptEntriesFromHap` 需独立 TC；本 Task 暂不在 scope，留作后续） |
| AC-6 | spec.md | 双端 TC 名称 + 验证模式一致（人工 review） |

### 规则映射

| Rule ID | Must / Must Not |
|---------|-----------------|
| hapsigner profile H-2 | Must：双端对同一 module.json 解析结果一致。TC 设计保证双端覆盖同一输入 → 同一输出 |
| hapsigner profile H-7 | Must：Java 和 C++ 是否都有单元测试覆盖？本 Task 直接满足 |
| hapsigner profile H-8 | Must：Java 是否通过 `mvn package` 编译成功？单测通过？本 Task 满足 Java 部分 |
| hapsigner profile H-9 | Must：C++ 实现是否完成手动编译验证？本 Task 用户手动验证（已确认） |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | T1, T2 | 测试目标是被 T1/T2 修复后的方法；必须先修复后测试 |

### 完成判据

- Java 端：
  - `HapUtilsTest.java` 文件创建，4 个 TC 实现
  - `mvn test` 在 `hapsigntool/` 目录执行成功，所有 TC 通过
  - 测试结果输出在 `target/surefire-reports/` 下
- C++ 端：
  - `hap_utils_skill_test.cpp` 文件创建，4 个 TC 实现
  - 测试源码无编译错误（用户手动 `gn gen && ninja` 验证）
  - gtest 全部 4 个 TC 通过（用户手动运行后确认）
- 完成证据记录在 task.md 末尾

### 停止条件

- Java `mvn test` 失败：停止，回传失败 TC 名 + 错误信息
- C++ 测试源码编译失败：停止，回传编译错误信息
- 现有 native SO 签名测试因本次 TC 设计而失败：停止，禁止修改现有测试，定位冲突后回传
- 双端测试对同一输入产生不同结果（违反 hapsigner profile H-2）：停止，禁止合并

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 新增 | `hapsigntool/hap_sign_tool_lib/src/test/java/com/ohos/hapsigntool/codesigning/utils/HapUtilsTest.java` | Java 端单测 |
| 新增 | `hapsigntool_cpp_test/unittest/codeSigning/utils/hap_utils_skill_test.cpp` | C++ 端单测 |
| 测试 | `hapsigntool/hap_sign_tool_lib/src/test/resources/module_normal.json`（建议） | Java 端测试资源 |
| 测试 | `hapsigntool/hap_sign_tool_lib/src/test/resources/module_empty.json`（建议） | Java 端测试资源 |
| 测试 | `hapsigntool/hap_sign_tool_lib/src/test/resources/module_no_skillprofiles.json`（建议） | Java 端测试资源 |
| 测试 | `hapsigntool/hap_sign_tool_lib/src/test/resources/module_invalid.json`（建议） | Java 端测试资源 |

## 代码变更规格

### 新增文件 1: `HapUtilsTest.java`

**用途：** Java 端单测 `HapUtils.getSkillNamesFromJson(JarFile)`

**目标代码：**
```java
package com.ohos.hapsigntool.codesigning.utils;

import com.google.gson.JsonParseException;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class HapUtilsTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private File createJarWithModuleJson(String content) throws IOException {
        File jarFile = folder.newFile("test.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jarFile))) {
            ZipEntry entry = new ZipEntry("module.json");
            zos.putNextEntry(entry);
            zos.write(content.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return jarFile;
    }

    @Test
    public void getSkillNamesFromJson_normal_returnsAllNames() throws IOException {
        String json = "{\"module\":{\"skillProfiles\":[{\"name\":\"MySkill1\"},{\"name\":\"MySkill2\"}]}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assert.assertEquals(2, result.size());
            Assert.assertEquals("MySkill1", result.get(0));
            Assert.assertEquals("MySkill2", result.get(1));
        }
    }

    @Test
    public void getSkillNamesFromJson_emptyArray_returnsEmptyList() throws IOException {
        String json = "{\"module\":{\"skillProfiles\":[]}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assert.assertTrue(result.isEmpty());
        }
    }

    @Test
    public void getSkillNamesFromJson_noSkillProfilesField_returnsEmptyList() throws IOException {
        String json = "{\"module\":{}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assert.assertTrue(result.isEmpty());
        }
    }

    @Test
    public void getSkillNamesFromJson_invalidJson_returnsEmptyList() throws IOException {
        String json = "not a valid json";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assert.assertTrue(result.isEmpty());
        }
    }
}
```

### 新增文件 2: `hap_utils_skill_test.cpp`

**用途：** C++ 端单测 `HapUtils::GetSkillNamesFromJson`

**目标代码：**
```cpp
#include <gtest/gtest.h>
#include "hap_utils.h"

namespace OHOS {
namespace SignatureTools {

class HapUtilsSkillTest : public testing::Test {};

// TC-C-1 正常
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_Normal_ReturnsAllNames)
{
    std::string json = R"({"module":{"skillProfiles":[{"name":"MySkill1"},{"name":"MySkill2"}]}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "MySkill1");
    EXPECT_EQ(result[1], "MySkill2");
}

// TC-C-2 空数组
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_EmptyArray_ReturnsEmpty)
{
    std::string json = R"({"module":{"skillProfiles":[]}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_TRUE(result.empty());
}

// TC-C-3 缺字段
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_NoSkillProfiles_ReturnsEmpty)
{
    std::string json = R"({"module":{}})";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_TRUE(result.empty());
}

// TC-C-4 非法 JSON
TEST_F(HapUtilsSkillTest, GetSkillNamesFromJson_InvalidJson_ReturnsEmpty)
{
    std::string json = "not a valid json";
    auto result = HapUtils::GetSkillNamesFromJson(json);
    ASSERT_TRUE(result.empty());
}

}  // namespace SignatureTools
}  // namespace OHOS
```

## BUILD.gn 变更

```
文件路径: N/A
变更说明: 不修改 BUILD.gn（仓内 gtest 构建由用户决定如何纳入；本 Task 仅创建测试源码）
```

**说明：** Java 端无需 pom.xml 变更（Maven 自动发现 `src/test/java` 下的测试类）。C++ 端如需纳入 BUILD.gn，由用户在 Stage 4 手动添加 target（不在本 Task 范围）。

## context-references

```yaml
context-queries:
  - repo: "developtools/hapsigner"
    query: "现有 HapUtils 单测样例（ProfileTest / KeyStoreTest 等）"
  - repo: "developtools/hapsigner"
    query: "现有 C++ gtest 单测样例（cms_utils_test.cpp / fs_digest_utils_test.cpp）"
  - repo: "developtools/hapsigner"
    query: "cJSON API 使用样例（hap_utils.cpp）"
```

## 验证检查清单

- [ ] `HapUtilsTest.java` 创建
- [ ] `hap_utils_skill_test.cpp` 创建
- [ ] Java 4 个 TC 实现完整
- [ ] C++ 4 个 TC 实现完整
- [ ] Java `mvn test` 通过
- [ ] C++ 测试源码无编译错误（用户手动）
- [ ] C++ gtest 通过（用户手动）
- [ ] 未修改文件范围外的内容
- [ ] 完成证据已记录

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| Java 单测 | `cd hapsigntool && mvn -pl hap_sign_tool_lib test -Dtest=HapUtilsTest` | **PASS**（Tests run: 4, Failures: 0, Errors: 0, Skipped: 0） |
| Java 全量回归 | `cd hapsigntool && mvn -pl hap_sign_tool_lib test` | **PASS**（Tests run: 23, Failures: 0, Errors: 0, Skipped: 0；含 4 新增 + 19 既有） |
| C++ 编译 | 用户手动 `cd hapsigntool_cpp_test && gn gen && ninja hap_utils_skill_test` | TBD（用户填；本会话无法构建） |
| C++ 运行 | 用户手动运行 gtest 二进制 | TBD（用户填 4 个 TC 均 PASS） |
| Python E2E | `python3 tools/test/scripts_signing_e2e.py` | **PASS**（9/9 TC；含 AC-5 嵌套子目录严格验证 + AC-4 warn-and-continue 验证） |
| 测试驱动 bug 修复 | F3 (`HapUtils.java:265` `JsonParseException` 扩 `IllegalStateException`) | 已修复 |
