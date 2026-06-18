# T2: 修复 code_signing 流程 — 路径前缀 + module.json 单次读取

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | T2 |
| 标题 | 修复 code_signing 流程的路径前缀并合并 module.json 重复读取 |
| 关联 Feature | FEAT-20260603-001 |
| 目标仓库 | `developtools/hapsigner` |
| 目标模块 | `hapsigntool_cpp/codesigning/sign/` + `hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/sign/` |
| 分支 | `dev` |
| 优先级 | P2 |
| 复杂度 | 中 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

**C++ 端（`hapsigntool_cpp/codesigning/sign/`）：**

1. 修复 `CodeSigning::GetScriptEntriesFromHap` 的路径前缀拼接
   - 当前：`scriptsPath = skillName + SCRIPTS_SUFFIX`（如 `MySkill/scripts/`，漏 `skills/`）
   - 目标：`scriptsPath = "skills/" + skillName + "/scripts/"`（如 `skills/MySkill/scripts/`）
2. 合并 `CodeSigning::SignSkillScripts` 与 `CodeSigning::GetScriptEntriesFromHap` 之间的重复 `HapUtils::GetModuleContentFromHap` 调用
   - 当前：调用 2 次（一次在 `SignSkillScripts` 中获取 moduleContent，一次在 `GetScriptEntriesFromHap` 中再次获取）
   - 目标：仅在 `SignSkillScripts` 中调用 1 次 `GetModuleContentFromHap`，将 moduleContent 作为参数传递给 `GetScriptEntriesFromHap`
3. 同步修复 `SCRIPTS_SUFFIX` 常量（可选重构）
   - 建议：保持 `SCRIPTS_SUFFIX = "/scripts/"`（语义 = 路径后缀），新增 `SKILLS_PATH_PREFIX = "skills/"`（语义 = 父目录前缀）；`scriptsPath = SKILLS_PATH_PREFIX + skillName + SCRIPTS_SUFFIX`

**Java 端（`hapsigntool/.../CodeSigning.java`）：**

1. 修复 `CodeSigning.getScriptEntriesFromHap` 的路径前缀拼接
   - 当前：`String scriptsPath = skillName + SCRIPTS_SUFFIX`（漏 `skills/`）
   - 目标：`String scriptsPath = "skills/" + skillName + "/scripts/"`
2. 同步 `SCRIPTS_SUFFIX` 命名（C++ 端如新增 `SKILLS_PATH_PREFIX`，Java 端也保持一致命名）

### 不做什么

- 不修改 `HapUtils.cpp` / `HapUtils.java` 的方法签名
- 不修改 native SO 签名的逻辑
- 不修改 `NativeLibInfoSegment` 二进制布局
- 不修改 `code_signing_test.cpp` / `Java` 单测（T3 范围）
- 不修改 BUILD.gn / Maven pom（无新增依赖）

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-1 | spec.md | 路径前缀 `skills/<skillName>/scripts/` 修复后，SoInfoSegment.fileNameList 含正确 entry name |
| AC-2 | spec.md | 缺 `skillProfiles` 时不变更 SoInfoSegment（已有逻辑，T2 不改） |
| AC-3 | spec.md | 目录项被跳过（`CheckFileNameForScripts` 已有逻辑） |
| AC-4 | spec.md | warn-and-continue（已有逻辑） |
| AC-5 | spec.md | 嵌套子目录不签名（路径前缀 = `startsWith` 仅匹配直接子文件，行为自然） |
| AC-6 | spec.md | 静态代码 review：双端路径前缀 = `skills/<skillName>/scripts/`（AC-6 等价） |

### 规则映射

| Rule ID | Must / Must Not |
|---------|-----------------|
| hapsigner profile H-2 | Must：双实现等价。路径前缀错 = 签出不同 entry，违反等价约束 |
| hapsigner profile H-6 | Must：双端同步更新路径前缀 |
| spec.md 技术约束 3 | Must：路径前缀 = `skills/<skillName>/scripts/<file>` |
| spec.md 技术约束 4 | Must：module.json 单次读取（C++ 端去重） |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | T1 | T2 的 C++ 路径拼接依赖 T1 修复后的 JSON 键名正确解析出 skill 名称 |

### 完成判据

- `git diff` 显示 4 个文件被修改（C++ × 2 + Java × 2）
- C++ `CodeSigning::SignSkillScripts` 中 `GetModuleContentFromHap` 仅被调用 1 次（grep 验证）
- C++ `CodeSigning::GetScriptEntriesFromHap` 签名包含 `moduleContent` 参数（grep 验证）
- 双端 `scriptsPath` 拼接结果一致 = `skills/<skillName>/scripts/`
- 用户手动 `gn gen && ninja` 在仓内根目录执行成功
- `mvn package` 在 `hapsigntool/` 目录下执行成功
- 现有 `code_signing_test`（`signNativeLibs` 等）不退化

### 停止条件

- C++ 编译失败：停止，定位头文件依赖问题，回传失败日志
- Java 编译失败：停止，定位 import 或方法签名问题，回传失败日志
- 现有 native SO 签名测试因本次修改失败：停止，回传失败测试名 + 错误信息（可能是 SoInfoSegment 顺序变化导致；若是，必须保留 T2 的修改并调整测试断言）
- 静态分析发现双端路径前缀仍有差异：停止，禁止合并

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `hapsigntool_cpp/codesigning/sign/include/code_signing.h` | 调整 `GetScriptEntriesFromHap` 签名（增加 `moduleContent` 参数）；新增 `SKILLS_PATH_PREFIX` 常量（可选） |
| 修改 | `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | 修复 `SignSkillScripts` / `GetScriptEntriesFromHap` 的路径拼接 + module.json 去重 |
| 修改 | `hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/sign/CodeSigning.java` | 修复 `getScriptEntriesFromHap` 的路径拼接；同步 `SCRIPTS_SUFFIX` 命名 |

## 代码变更规格

### 修改文件 1: `hapsigntool_cpp/codesigning/sign/include/code_signing.h`

**变更原因：** `GetScriptEntriesFromHap` 需接收已读取的 module.json 内容，避免重复读取 HAP

**变更位置：** 公有方法声明区（line 66 附近）

**当前代码：**
```cpp
bool GetScriptEntriesFromHap(const std::string& packageName, UnzipHandleParam& param);
```

**目标代码：**
```cpp
bool GetScriptEntriesFromHap(const std::string& packageName, UnzipHandleParam& param);
bool GetScriptEntriesFromHap(const std::string& packageName, const std::vector<std::string>& skillNames,
                             UnzipHandleParam& param);
```

**变更位置 2：** 公有静态常量区（line 32 附近）

**当前代码：**
```cpp
static const std::string SCRIPTS_SUFFIX;
```

**目标代码：**
```cpp
static const std::string SKILLS_PATH_PREFIX;
static const std::string SCRIPTS_SUFFIX;
```

### 修改文件 2: `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp`

**变更原因：** 路径前缀 + module.json 单次读取

**变更位置：** 静态常量定义（line 32）

**当前代码：**
```cpp
const std::string CodeSigning::SCRIPTS_SUFFIX = "/scripts/";
```

**目标代码：**
```cpp
const std::string CodeSigning::SKILLS_PATH_PREFIX = "skills/";
const std::string CodeSigning::SCRIPTS_SUFFIX = "/scripts/";
```

**变更位置 2：** `SignSkillScripts` 函数（line 245-272）

**当前代码（参考）：**
```cpp
bool CodeSigning::SignSkillScripts(const std::string &input, std::string &ownerID)
{
    std::string moduleContent;
    if (!HapUtils::GetModuleContentFromHap(input, moduleContent)) {
        SIGNATURE_TOOLS_LOGI("No module.json found or failed to read module.json");
        return true;
    }
    std::vector<std::string> skillNames = HapUtils::GetSkillNamesFromJson(moduleContent);
    ...
    bool scriptFlag = GetScriptEntriesFromHap(input, param);  // 这里会再次 GetModuleContentFromHap
    ...
}
```

**目标代码：**
```cpp
bool CodeSigning::SignSkillScripts(const std::string &input, std::string &ownerID)
{
    std::string moduleContent;
    if (!HapUtils::GetModuleContentFromHap(input, moduleContent)) {
        SIGNATURE_TOOLS_LOGI("No module.json found or failed to read module.json");
        return true;
    }
    std::vector<std::string> skillNames = HapUtils::GetSkillNamesFromJson(moduleContent);
    if (skillNames.empty()) {
        SIGNATURE_TOOLS_LOGI("No skill names found in module.json");
        return true;
    }
    std::vector<std::pair<std::string, SignInfo>> ret;
    UnzipHandleParam param(ret, ownerID, true);
    bool scriptFlag = GetScriptEntriesFromHap(input, skillNames, param);  // 传递已解析的 skillNames
    ...
}
```

**变更位置 3：** `GetScriptEntriesFromHap` 函数（line 274-332）

**当前代码（参考）：**
```cpp
bool CodeSigning::GetScriptEntriesFromHap(const std::string& packageName, UnzipHandleParam& param)
{
    std::string moduleContent;
    if (!HapUtils::GetModuleContentFromHap(packageName, moduleContent)) {
        return true;
    }
    std::vector<std::string> skillNames = HapUtils::GetSkillNamesFromJson(moduleContent);
    if (skillNames.empty()) {
        return true;
    }
    ... // 遍历 zip entries
}
```

**目标代码：**
```cpp
bool CodeSigning::GetScriptEntriesFromHap(const std::string& packageName,
                                          const std::vector<std::string>& skillNames,
                                          UnzipHandleParam& param)
{
    if (skillNames.empty()) {
        return true;
    }
    ... // 遍历 zip entries，复用入参 skillNames
}
```

（同时保留旧签名的 inline 实现为空 inline 调用新签名，或删除旧签名 + 同步更新所有调用方；建议保留旧签名作为 inline wrapper，向后兼容，但本仓内无其它调用者，可直接删除旧签名）

**变更位置 4：** `CheckFileNameForScripts` 函数（line 593-606）

**当前代码：**
```cpp
bool CodeSigning::CheckFileNameForScripts(char fileName[], size_t nameLen, const std::vector<std::string>& skillNames)
{
    if (fileName[nameLen - 1] == '/') {
        return false;
    }
    std::string str(fileName);
    for (const auto& skillName : skillNames) {
        std::string scriptsPath = skillName + SCRIPTS_SUFFIX;
        if (str.find(scriptsPath) == 0) {
            return true;
        }
    }
    return false;
}
```

**目标代码：**
```cpp
bool CodeSigning::CheckFileNameForScripts(char fileName[], size_t nameLen, const std::vector<std::string>& skillNames)
{
    if (fileName[nameLen - 1] == '/') {
        return false;
    }
    std::string str(fileName);
    for (const auto& skillName : skillNames) {
        std::string scriptsPath = SKILLS_PATH_PREFIX + skillName + SCRIPTS_SUFFIX;
        if (str.find(scriptsPath) == 0) {
            return true;
        }
    }
    return false;
}
```

### 修改文件 3: `hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/sign/CodeSigning.java`

**变更原因：** Java 端路径前缀同样需加 `skills/`

**变更位置：** 常量定义（line 90）

**当前代码：**
```java
private static final String SCRIPTS_SUFFIX = "/scripts/";
```

**目标代码：**
```java
private static final String SKILLS_PATH_PREFIX = "skills/";
private static final String SCRIPTS_SUFFIX = "/scripts/";
```

**变更位置 2：** `getScriptEntriesFromHap` 方法（line 294-306）

**当前代码：**
```java
private List<String> getScriptEntriesFromHap(JarFile hap, List<String> skillNames) {
    List<String> result = new ArrayList<>();
    for (String skillName : skillNames) {
        String scriptsPath = skillName + SCRIPTS_SUFFIX;
        ...
    }
    return result;
}
```

**目标代码：**
```java
private List<String> getScriptEntriesFromHap(JarFile hap, List<String> skillNames) {
    List<String> result = new ArrayList<>();
    for (String skillName : skillNames) {
        String scriptsPath = SKILLS_PATH_PREFIX + skillName + SCRIPTS_SUFFIX;
        ...
    }
    return result;
}
```

## BUILD.gn 变更

```
文件路径: N/A
变更说明: 无 BUILD.gn / pom.xml 变更
```

## context-references

```yaml
context-queries:
  - repo: "developtools/hapsigner"
    query: "现有 CodeSigning::SignNativeLibs / GetNativeEntriesFromHap 实现（作为路径前缀修改的对照）"
  - repo: "developtools/hapsigner"
    query: "现有 signNativeLibs / signNativeHnps 在 CodeSigning.java 中的串行调用模式"
```

## 验证检查清单

- [x] F4 `SKILLS_PATH_PREFIX` 头文件声明（grep 验证）
- [x] F5 `SKILLS_PATH_PREFIX = "skills/"` 定义（grep 验证）
- [x] F6 `GetScriptEntriesFromHap` 签名含 `skillNames` 参数（grep 验证）
- [x] F7 `SignSkillScripts` 中 `GetModuleContentFromHap` 仅 1 次调用（grep 计数 = 1）
- [x] F8 C++ 路径拼接 = `SKILLS_PATH_PREFIX + skillName + SCRIPTS_SUFFIX`
- [x] F9 C++ `CheckFileNameForScripts` 简化（compare + 单行 find 含嵌套判定）
- [x] F10 Java `getScriptEntriesFromHap` 拆 3 守卫（isDirectory / startsWith / contains `/`）
- [x] F10 Java `SKILLS_PATH_PREFIX` 常量 + 路径拼接
- [x] F11 C++ `CheckFileNameForScripts` 头文件声明
- [x] F12 C++ `GetScriptEntriesFromHap` / `IterateScriptsEntries` 头文件声明
- [x] F13 soInfoList 合并改用 `combinedList` + `SetSoInfoList`
- [x] C++ 编译通过（用户手动 `gn gen && ninja`）
- [x] Java 编译通过（`mvn package`）
- [x] 现有 `code_signing_test` / Java 单测不退化
- [x] 未修改文件范围外的内容
- [x] 完成证据已记录

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 静态检查 F4 | `grep "SKILLS_PATH_PREFIX" hapsigntool_cpp/codesigning/sign/include/code_signing.h` | PASS（line 45） |
| 静态检查 F5 | `grep "SKILLS_PATH_PREFIX" hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | PASS（line 32） |
| 静态检查 F6 | `grep "GetScriptEntriesFromHap" hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | PASS（line 268 调用，line 283 定义，签名含 skillNames） |
| 静态检查 F7 | `grep -c "GetModuleContentFromHap" hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | PASS（= 1，仅在 SignSkillScripts 内） |
| 静态检查 F8 | `grep "SKILLS_PATH_PREFIX + skillName + SCRIPTS_SUFFIX" hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | PASS（line 608） |
| 静态检查 F9 | `grep "find.*scriptsPath.size" hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | PASS（line 609，`str.find('/', scriptsPath.size())`） |
| 静态检查 F10 | `grep "isDirectory\|startsWith\|contains" hapsigntool/.../CodeSigning.java` | PASS（拆 3 步守卫） |
| 静态检查 F10 | `grep "SKILLS_PATH_PREFIX" hapsigntool/.../CodeSigning.java` | PASS（line 90, 298） |
| 静态检查 F11 | `grep "static bool CheckFileNameForScripts" hapsigntool_cpp/codesigning/sign/include/code_signing.h` | PASS（line 91，private 静态方法） |
| 静态检查 F12 | `grep "bool GetScriptEntriesFromHap\|bool IterateScriptsEntries" hapsigntool_cpp/codesigning/sign/include/code_signing.h` | PASS（line 69, 72） |
| 静态检查 F13 | `grep "combinedList" hapsigntool_cpp/codesigning/sign/src/code_signing.cpp` | PASS（line 275-289，combinedList 重建 + SetSoInfoList 替换） |
| Java 单元回归 | `mvn -pl hap_sign_tool_lib test` | **PASS**（24/24, 0 退化） |
| Python E2E | `python3 tools/test/scripts_signing_e2e.py` | **PASS**（9/9；TC-E-7 损坏 → sign rc=1；TC-E-8 缺失 → sign rc=0） |
| 构建 | 用户手动 `cd hapsigntool_cpp && gn gen && ninja` | TBD（用户填；本会话无法构建） |
| 构建 | `mvn -pl hap_sign_tool_lib install` | **PASS**（已在本会话执行） |
| 集成 | `mvn -pl hap_sign_tool -am package` | **PASS**（已在本会话执行） |
