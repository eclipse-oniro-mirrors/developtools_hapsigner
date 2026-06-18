# T1: 修复 hap_utils 模块 — JSON 键名 + UTF-8 BOM

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | T1 |
| 标题 | 修复 hap_utils 模块的 JSON 键名 bug 并恢复 BOM |
| 关联 Feature | FEAT-20260603-001 |
| 目标仓库 | `developtools/hapsigner` |
| 目标模块 | `hapsigntool_cpp/hap/utils/` |
| 分支 | `dev` |
| 优先级 | P2 |
| 复杂度 | 低 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

1. 修复 `HapUtils::GetSkillNamesFromJson` 中 module.json skill 数组的 JSON 键名
   - 当前：`cJSON_GetObjectItemCaseSensitive(moduleObj, "skills")`（错）
   - 目标：`cJSON_GetObjectItemCaseSensitive(moduleObj, "skillProfiles")`（与 Java 端一致）
2. 同步修复日志输出
   - 当前：`"module.json has no skills key or skills value is not an array"`
   - 目标：`"module.json has no skillProfiles key or skillProfiles value is not an array"`
3. 恢复 `hap_utils.h` 和 `hap_utils.cpp` 首行 UTF-8 BOM
   - 当前被误删（`/*` 开头）
   - 目标：恢复 `﻿/*`（与仓内其它文件风格一致）

### 不做什么

- 不修改 `HapUtils` 类的其它方法（如 `GetAppIdentifier`、`ReadFileToByteBuffer` 等）
- 不修改 `GetModuleContentFromHap`（它在 T2 中作为路径串联调用，不修改其实现）
- 不修改 `code_signing.cpp` / `code_signing.h`（T2 范围）
- 不修改 Java 端任何文件
- 不添加新测试用例（T3 范围）

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-1 | spec.md | 通过 JSON 键名修复使 C++ 端能正确解析 `skillProfiles`，与 Java 端等价 |
| AC-2 | spec.md | 缺 `skillProfiles` 时返回空 vector（与 Java 端行为一致） |
| AC-4 | spec.md | JSON 解析失败 / 键名缺失时 warn-and-continue（已实现，本次仅修键名） |
| AC-6 | spec.md | 静态代码 review：JSON 键名跨端 = `skillProfiles` |

### 规则映射

| Rule ID | Must / Must Not |
|---------|-----------------|
| hapsigner profile H-2 | Must：双实现等价。键名错 = 不等价，必须修复 |
| hapsigner profile H-6 | Must：双端同步更新 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| 无 | — | T1 是入口 Task，无前置依赖 |

### 完成判据

- `git diff` 显示 2 个文件被修改（`hap_utils.h`、`hap_utils.cpp`）
- `grep "skillProfiles" hapsigntool_cpp/hap/utils/src/hap_utils.cpp` 有 2 处匹配（`cJSON_GetObjectItemCaseSensitive` + 日志）
- `grep '"skills"' hapsigntool_cpp/hap/utils/src/hap_utils.cpp` 无匹配（确认已清除）
- `head -c 3 hapsigntool_cpp/hap/utils/include/hap_utils.h | xxd` 输出 `efbbbf`（UTF-8 BOM）
- `head -c 3 hapsigntool_cpp/hap/utils/src/hap_utils.cpp | xxd` 输出 `efbbbf`（UTF-8 BOM）
- 用户手动 `gn gen && ninja` 在仓内根目录执行成功

### 停止条件

- `gn gen` 失败：停止，定位 cJSON 头路径或 BUILD.gn 配置问题，回传失败日志
- 现有 `code_signing_test` 等回归测试因本次修改失败：停止，回传失败测试名 + 错误信息
- 仓内其它文件有同步 BOM 缺失（不是本次范围）：记录但不处理

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `hapsigntool_cpp/hap/utils/src/hap_utils.cpp` | JSON 键名 `"skills"` → `"skillProfiles"`；日志同步；恢复首行 UTF-8 BOM |
| 修改 | `hapsigntool_cpp/hap/utils/include/hap_utils.h` | 恢复首行 UTF-8 BOM（无逻辑变更） |

## 代码变更规格

### 修改文件 1: `hapsigntool_cpp/hap/utils/src/hap_utils.cpp`

**变更原因：** JSON 键名错（C++ 用 `skills`，Java 用 `skillProfiles`），违反 hapsigner profile 双端等价约束

**变更位置：** `HapUtils::GetSkillNamesFromJson` 函数（line ~137-141）

**当前代码（参考）：**
```cpp
cJSON* skillsArray = cJSON_GetObjectItemCaseSensitive(moduleObj, "skills");
if (skillsArray == nullptr || !cJSON_IsArray(skillsArray)) {
    SIGNATURE_TOOLS_LOGI("module.json has no skills key or skills value is not an array");
    cJSON_Delete(root);
    return skillNames;
}
```

**目标代码：**
```cpp
cJSON* skillsArray = cJSON_GetObjectItemCaseSensitive(moduleObj, "skillProfiles");
if (skillsArray == nullptr || !cJSON_IsArray(skillsArray)) {
    SIGNATURE_TOOLS_LOGI("module.json has no skillProfiles key or skillProfiles value is not an array");
    cJSON_Delete(root);
    return skillNames;
}
```

**变更位置 2：** 文件首行（line 1）

**当前代码：**
```
/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
```

**目标代码：**
```
﻿/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
```

（注：首字节 `EF BB BF` 是 UTF-8 BOM 标记，需在文件最开头插入 3 字节）

### 修改文件 2: `hapsigntool_cpp/hap/utils/include/hap_utils.h`

**变更原因：** BOM 被误删，与仓内其它文件风格不一致

**变更位置：** 文件首行（line 1）

**当前代码：**
```
/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
```

**目标代码：**
```
﻿/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
```

## BUILD.gn 变更

```
文件路径: N/A
变更说明: 无 BUILD.gn 变更
```

**说明：** `hapsigntool_cpp/hap/utils/BUILD.gn` 已声明 `cjson_static` 依赖（用户在 bundle.json 查证），无需修改。

## context-references

```yaml
context-queries:
  - repo: "developtools/hapsigner"
    query: "现有 GetSkillNamesFromJson 实现 + cJSON 用法"
  - repo: "developtools/hapsigner"
    query: "仓内其它 .cpp/.h 文件首行是否带 UTF-8 BOM（参考风格）"
```

## 验证检查清单

- [ ] JSON 键名 = `skillProfiles`（grep 验证）
- [ ] 日志文本含 `skillProfiles`（grep 验证）
- [ ] `hap_utils.h` 首 3 字节 = `EF BB BF`（xxd 验证）
- [ ] `hap_utils.cpp` 首 3 字节 = `EF BB BF`（xxd 验证）
- [ ] C++ 编译通过（用户手动 `gn gen && ninja`）
- [ ] 未修改文件范围外的内容
- [ ] 完成证据已记录

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 静态检查 | `grep -n "skillProfiles" hapsigntool_cpp/hap/utils/src/hap_utils.cpp` | PASS（line 137, 139） |
| 静态检查 | `grep -n '"skills"' hapsigntool_cpp/hap/utils/src/hap_utils.cpp` | PASS（无匹配，旧键名已清除） |
| 静态检查 | `head -c 3 hapsigntool_cpp/hap/utils/include/hap_utils.h \| od -An -tx1` | PASS（`ef bb bf`） |
| 静态检查 | `head -c 3 hapsigntool_cpp/hap/utils/src/hap_utils.cpp \| od -An -tx1` | PASS（`ef bb bf`） |
| 构建 | 用户手动 `cd hapsigntool_cpp && gn gen && ninja` | TBD（用户填；本会话无法构建） |
