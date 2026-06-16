# 特性规格

> 固化用户可见行为和验收标准。本特性复杂度为"简单"，跳过 design.md，本节"技术约束"段承载关键架构决策。

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | HAP 内 skills/<skillName>/scripts/ 脚本目录代码签名 |
| 特性编号 | FEAT-20260603-001 |
| 所属 Epic | 无（独立特性） |
| 优先级 | P2 |
| 目标版本 | TBD（随仓合入） |
| SIG 归属 | hapsigner |
| 状态 | Draft |
| 复杂度 | 简单 |
| Profile | hapsigner |
| 关联 manifest | `.specs/features/scripts-signing/manifest.md` |

## 技术约束

> 替代 design.md（简单级别跳过）。本节为架构层面的硬约束，对应实现必须满足。

1. **复用 NativeLibInfoSegment（SoInfoSegment）**：脚本签名结果与 native SO 签名结果共享同一 segment，不引入新的 ScriptInfoSegment。理由 = 现有 fs-verity + LocalSigner 机制已满足需求，引入新 segment 会改动 CodeSignBlockHeader、size 计算、verify 端。
2. **JSON 键名 = `skillProfiles`**：从 module.json 解析 skill 列表时使用 `skillProfiles`（不是 `skills`）。Java 与 C++ 端必须使用相同键名。
3. **路径匹配 = `skills/<skillName>/scripts/<file>`**：仅匹配直接子文件，不递归子目录。
4. **module.json 单次读取**：C++ 端 `SignSkillScripts` 与 `GetScriptEntriesFromHap` 必须共享一次 `GetModuleContentFromHap` 结果，不得重复打开 HAP。
5. **warn-and-continue 错误处理**：module.json 缺失、损坏、JSON 解析失败时，记录 warn 日志，跳过 scripts 签名步骤，继续处理 native SO。
6. **双实现等价**：Java 端与 C++ 端在同一 HAP + 同一 profile 参数下，SoInfoSegment 的 entry name 列表必须完全相同（hapsigner profile 硬约束）。

## 本次变更范围（Delta）

> lineage: new-on-legacy（在已有 native SO 签名能力上扩展 scripts 签名）

| 类型 | 内容 | 说明 |
|------|------|------|
| ADDED | C++ `HapUtils::GetSkillNamesFromJson(const std::string& moduleJson)` | 内部方法；从 module.json 文本解析 skill 名称列表 |
| ADDED | C++ `HapUtils::GetModuleContentFromHap(const std::string& hapPath, std::string& moduleContent)` | 内部方法；从 HAP 读取 module.json 文本 |
| ADDED | C++ `CodeSigning::SignSkillScripts(const std::string& input, std::string& ownerID)` | 内部方法；串联 module.json 读取 + skill 名称解析 + 脚本条目收集 + 签名 |
| ADDED | C++ `CodeSigning::GetScriptEntriesFromHap(const std::string& packageName, UnzipHandleParam& param)` | 内部方法；遍历 HAP entries，按 `skills/<skillName>/scripts/` 前缀匹配 |
| ADDED | C++ `CodeSigning::CheckFileNameForScripts(...)` | 内部静态方法；判定某 entry 是否为 scripts 下的待签文件 |
| ADDED | C++ `CodeSigning::SCRIPTS_SUFFIX` 常量（`/scripts/`） | 与 `LIBS_PATH_PREFIX` 对齐 |
| ADDED | Java `HapUtils.getSkillNamesFromJson(JarFile inputJar)` | 内部静态方法；与 C++ 端等价 |
| ADDED | Java `CodeSigning.signSkillScripts(File input, String ownerID)` | 私有方法；与 C++ 端等价 |
| ADDED | Java `CodeSigning.getScriptEntriesFromHap(JarFile hap, List<String> skillNames)` | 私有方法；与 C++ 端等价 |
| ADDED | Java `CodeSigning.SCRIPTS_SUFFIX` 常量（`/scripts/`） | 与 C++ 端对齐 |
| MODIFIED | C++ `CodeSigning::GetCodeSignBlock(...)` | 在 `SignNativeLibs` 之后插入 `SignSkillScripts` 调用 |
| MODIFIED | Java `CodeSigning.getCodeSignBlock(...)` | 在 `signNativeLibs` + `signNativeHnps` 之后插入 `signSkillScripts` 调用 |
| MODIFIED | C++ `HapUtils::GetSkillNamesFromJson` | JSON 键名从 `skills` 改为 `skillProfiles`（bug fix） |
| MODIFIED | C++ `hap_utils.h` / `hap_utils.cpp` | 恢复首行 UTF-8 BOM |

## 输入文档

| 文档 | 路径 | 状态 |
|------|------|------|
| Requirement | `.specs/features/scripts-signing/proposal.md` | Approved (Stage 1) |

## 用户故事

### US-1: HAP scripts 目录代码签名

**作为** HAP 签名工具使用者（应用开发者/系统集成商）,
**我想要** 在签名 HAP 时自动对 `skills/<skillName>/scripts/` 下所有非目录文件执行与 native SO 一致的代码签名,
**以便** 提升 HAP 包完整性保护能力，防止 scripts 内容被篡改后伪装成原包。

**验收标准：**

- **AC-1:** WHEN HAP 的 module.json 含 N 个 `skillProfiles` 项，第 i 个 skill 名称下有 K_i 个 `scripts/` 直接子文件 THEN `SoInfoSegment.fileNameList` 恰增 ΣK_i 条 entry，entry name 格式为 `skills/<skillName>/scripts/<file>`
- **AC-2:** WHEN HAP 的 module.json 不含 `skillProfiles` 字段 THEN `SoInfoSegment` 不变（与无 skillProfiles 的现有行为完全一致，向后兼容）
- **AC-3:** WHEN `skills/<skillName>/scripts/` 下的某项是目录 THEN 跳过该项，不写入 `SoInfoSegment`
- **AC-4:** 
  - WHEN HAP 缺少 module.json THEN 记录 warn 日志，跳过 scripts 签名步骤，继续处理 native SO（warn-and-continue）
  - WHEN HAP 的 module.json 损坏 / JSON 解析失败 THEN 抛出 `HapFormatException` 或 `ProfileException`，**终止签名流程**（签名工具不负责修复损坏文件）
  - WHEN `skillProfiles` 字段不是数组或不存在 THEN 视为空列表，scripts 签名子流程优雅降级（主签名不中断）
- **AC-5:** WHEN `skills/<skillName>/scripts/sub/x.js` 等嵌套子目录项存在 THEN 不被签名（不递归扫描）
- **AC-6:** WHEN Java 端与 C++ 端签名同一 HAP THEN 双方 `SoInfoSegment.fileNameList` 完全相同（双实现等价；hapsigner profile 硬约束；本轮仅做静态代码 review + 双端单测覆盖，等价性集成测试不在范围内）

## 验收追溯

| AC | 关联规则 | 关联 Task | 验证方式 | 证据 |
|----|----------|-----------|----------|------|
| AC-1 | FR-1, BR-1 | T1, T2 | Java 单测 + C++ 单测（手动）+ 代码静态检查 | TBD（Stage 3 完成后） |
| AC-2 | FR-1, BR-1 | T1, T2 | Java 单测 + C++ 单测（手动） | TBD |
| AC-3 | FR-2 | T2 | Java 单测 + C++ 单测（手动） | TBD |
| AC-4 | EX-1, EX-2, EX-3 | T1, T2 | Java 单测 + C++ 单测（手动） | TBD |
| AC-5 | BR-2 | T2 | Java 单测 + C++ 单测（手动） | TBD |
| AC-6 | BR-3 | T1, T2 | 静态代码 review（JSON 键名、路径前缀、EntryCollection 顺序） | TBD |

## 业务规则

| 编号 | 规则描述 | 约束条件 | 关联 AC |
|------|----------|----------|---------|
| BR-1 | 脚本签名范围为 `skills/<skillName>/scripts/` 下所有非目录文件 | 仅直接子文件；不含子目录 | AC-1, AC-2, AC-3, AC-5 |
| BR-2 | 不递归扫描 scripts 目录的子目录 | 即使子目录含文件也不签名 | AC-5 |
| BR-3 | Java 与 C++ 端 SoInfoSegment.entry name 列表等价 | 同一 HAP + 同一 profile 参数 | AC-6 |

## 功能规则

| 编号 | 规则描述 | 触发条件 | 作用对象 | 关联 AC |
|------|----------|----------|----------|---------|
| FR-1 | 在 `CodeSigning` 主流程中新增"脚本签名"步骤 | 在 `signNativeLibs` + `signNativeHnps`（Java）/`SignNativeLibs`（C++）之后；`updateCodeSignBlock` 之前 | HAP 签名主流程 | AC-1, AC-2, AC-6 |
| FR-2 | 仅签非目录文件 | 遍历 HAP entries 时按 entry.isDirectory 过滤 | HAP entries | AC-3 |

## 异常/豁免规则

| 编号 | 异常码/枚举 | 规则描述 | 触发条件 | 超时阈值 | 处理结果 | 关联 AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-1 | N/A | HAP 不含 module.json | `unzLocateFile("module.json", 0) != UNZ_OK`（C++）/ `inputJar.getJarEntry("module.json") == null`（Java） | N/A | warn-and-continue；跳过 scripts 签名 | AC-4 |
| EX-2 | `HapFormatException` / `ProfileException` | module.json 损坏 / 非法 JSON | `cJSON_ParseWithOpts` 返回 null（C++）/ `JsonParser.parseReader` 抛 `JsonParseException` 或 `IllegalStateException`（Java） | N/A | **抛异常；终止签名流程**（签名工具不负责修复损坏文件） | AC-4 |
| EX-3 | N/A | module.json 缺 `skillProfiles` 字段或 `skillProfiles` 不是数组 | C++：`cJSON_GetObjectItemCaseSensitive(moduleObj, "skillProfiles")` 为 null 或非数组；Java：`getAsJsonArray("skillProfiles")` 为 null 或 empty | N/A | 视为空列表；scripts 签名子流程优雅降级（主签名不中断） | AC-2, AC-4 |

## 恢复契约

> 本特性无独立恢复路径（离线工具，无事务）。warn-and-continue 路径（EX-1/EX-3）下整体流程继续；throw & abort 路径（EX-2）下整体流程终止。

| 编号 | 触发条件 | 恢复策略 | 恢复结果 | 约束 |
|------|----------|----------|----------|------|
| RC-1 | EX-1/EX-2/EX-3 触发 | 继续执行 native SO 签名；记录 warn 日志 | 整体签名流程不中断；SoInfoSegment 只含 native SO entry | N/A |

## 验证映射

| 编号 | 对应规格项 | 验证方式 | 验证重点 |
|------|------------|----------|----------|
| VM-1 | FR-1 / AC-1, AC-2, AC-6 | Java 单测 + C++ 单测（手动） | 入口流程中调用了 scripts 签名；SoInfoSegment 正确累加 |
| VM-2 | FR-2 / AC-3 | Java 单测 + C++ 单测（手动） | 目录项被跳过 |
| VM-3 | BR-2 / AC-5 | Java 单测 + C++ 单测（手动） | 嵌套子目录项不被签名 |
| VM-4 | EX-1 / AC-4 | Python E2E TC-E-8 | 缺失 module.json → sign rc=0 + verify rc=0（warn-and-continue） |
| VM-5 | EX-2 / AC-4 | Python E2E TC-E-7 | 非法 JSON → sign rc=1（抛异常终止） |
| VM-6 | EX-3 / AC-4, AC-2 | Java 单测 + Python E2E TC-E-5/TC-E-6 | 缺 skillProfiles → 视为空列表，不新增 entry |
| VM-7 | BR-3 / AC-6 | 静态代码 review + 双端单测对比 | JSON 键名一致 / 路径前缀一致 / EntryCollection 顺序一致 |

## API 变更分析

> 本特性为内部模块扩展，不涉及 Public/System API 变更。

### 新增 API

> 仅新增内部方法（静态/私有），不开放为 Public/System API。

| API 名称 | 开放范围 | 入参概要 | 返回值 | 错误码范围 | 功能描述 | 关联 AC |
|----------|----------|----------|--------|------------|----------|---------|
| `HapUtils::GetSkillNamesFromJson` | Internal（C++ 静态方法） | `const std::string& moduleJson` | `std::vector<std::string>` | N/A（异常时返回空 vector） | 从 module.json 文本解析 skillProfiles 数组的 name 字段列表 | AC-1, AC-2, AC-4 |
| `HapUtils::GetModuleContentFromHap` | Internal（C++ 静态方法） | `const std::string& hapPath`, `std::string& moduleContent`（out） | `bool` | N/A（失败时 moduleContent 清空） | 从 HAP 读取 module.json 文本到 out 参数 | AC-1, AC-4 |
| `CodeSigning::SignSkillScripts` | Internal（C++ 公有方法） | `const std::string& input`, `std::string& ownerID` | `bool` | N/A（失败返回 false） | 串联 module.json 读取 + skill 名称解析 + 脚本条目收集 + 签名 | AC-1, AC-2, AC-3, AC-4, AC-5, AC-6 |
| `HapUtils.getSkillNamesFromJson` | Internal（Java 静态方法） | `JarFile inputJar` | `List<String>` | 抛 `IOException` | 从 JarFile 读取 module.json 并解析 skillProfiles | AC-1, AC-2, AC-4 |
| `CodeSigning.signSkillScripts` | Internal（Java 私有方法） | `File input`, `String ownerID` | `List<Pair<String, SignInfo>>` | 抛 `IOException`, `FsVerityDigestException`, `CodeSignException` | 与 C++ 端 SignSkillScripts 等价 | AC-1, AC-2, AC-3, AC-4, AC-5, AC-6 |

### 变更/废弃 API

| API 名称 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|---------|
| N/A | N/A | N/A | N/A | N/A |

## 兼容性声明

- **已有 API 行为变更:** 否
- **配置文件格式变更:** 否
- **数据存储格式变更:** 否（复用 NativeLibInfoSegment 二进制布局）
- **最低支持版本:** N/A（仓内工具，不涉及对外 SDK）
- **API 版本号策略:** N/A
- **向后兼容:** 是 — HAP 不含 `skillProfiles` 时签名行为与现状完全一致（AC-2）

## 架构约束

| 关键约束 | 约束说明 | 影响 AC |
|----------|----------|---------|
| 复用 SoInfoSegment | 脚本签名结果必须与 native SO 共享 `NativeLibInfoSegment`，不新增 segment | AC-1, AC-6 |
| JSON 键名固定 | module.json skill 数组键名 = `skillProfiles` | AC-1, AC-4, AC-6 |
| 路径前缀固定 | 脚本 entry 路径前缀 = `skills/<skillName>/scripts/` | AC-1, AC-5, AC-6 |
| 单次读取 | 每次 CodeSigning 主流程只读一次 module.json | 性能（非功能性） |
| 错误处理策略 | module.json 异常 → warn-and-continue | AC-4 |

## 非功能性需求

> N/A 判定见 proposal.md 不涉及项确认。本节仅为适用项填写。

| 类型 | 指标/阈值 | 验证方式 | 证据 |
|------|-----------|----------|------|
| 性能 | module.json 单次读取；脚本签名在主流程中串行（不引入新线程池） | 代码静态检查 | TBD |
| 安全 | 复用 fs-verity + 私钥签名，无新密码学原语 | 代码 review | TBD |
| 可靠性 | module.json 异常时整体签名流程不中断（warn-and-continue） | 单测 AC-4 | TBD |
| 问题定位 | WARN 日志明示原因（"No module.json" / "Failed to parse module.json" / "skillProfiles not found"） | 单测 + 日志检查 | TBD |

## 多设备适配声明

> 本特性为签名工具，与设备类型无关。

| 设备类型 | 行为差异 | 规格/约束 | 验证方式 | 证据 |
|----------|----------|-----------|----------|------|
| 全部 | 无差异 | N/A | N/A | N/A |

## 全局特性影响

| 特性 | 适用？ | 结论 | 关联场景 |
|------|--------|------|----------|
| 无障碍 | 否 | 工具内部，无 UI | N/A |
| 大字体 | 否 | 同上 | N/A |
| 深色模式 | 否 | 同上 | N/A |
| 多窗口/分屏 | 否 | 同上 | N/A |
| 多用户 | 否 | 同上 | N/A |
| 版本升级 | 是 | 升级 hapsigner 工具后，签出新 HAP；旧 HAP 不需重新签名 | AC-2 |
| 生态兼容 | 是 | 旧版本 hapsigner 签出的 HAP（无 scripts 签名）仍可被新版本 verify | AC-2 |

## 行为场景（可选，Gherkin）

> 简单特性，6 条 AC 已覆盖核心场景；不在此展开 Gherkin。

## Spec 自审清单

- [x] 无"待定""TBD""TODO"等占位符（target_release.id = TBD 在 manifest 而非 spec，已与 profile 允许的"明确 TBD"对齐）
- [x] 所有 AC 使用 WHEN/THEN 格式，可独立测试
- [x] 范围边界明确（做什么/不做什么清晰）
- [x] 无语义模糊表述
- [x] AC 与业务规则/异常规则/恢复契约交叉一致

## context-references

```yaml
context-queries:
  - repo: "developtools/hapsigner"
    query: "现有 CodeSigning::SignNativeLibs / CodeSigning.signNativeLibs 实现模式"
  - repo: "developtools/hapsigner"
    query: "NativeLibInfoSegment / SoInfoSegment 数据结构布局"
  - repo: "developtools/hapsigner"
    query: "module.json skillProfiles schema 定义来源"
```

**关键文档：**
- 现有 native SO 签名入口：`hapsigntool_cpp/codesigning/sign/src/code_signing.cpp:226` / `hapsigntool/.../CodeSigning.java:263`
- 现有 NativeLibInfoSegment：`hapsigntool_cpp/codesigning/datastructure/include/native_lib_info_segment.h`
- 现有 module.json 解析样例：`hapsigntool/.../HapUtils.java:197 getHnpsFromJson`（hnpPackages 解析）
