# 需求文档

> 一份文档，从原始需求到基线结论。按阶段追加内容，不拆成多份独立文件。
> 当前阶段：**Stage 1 定义中**（澄清轮进行中，基线尚未固化）

## 一、原始需求

### 基本信息

| 字段 | 内容 |
|------|------|
| 需求ID | FEAT-20260603-001 |
| 需求名称 | HAP 内 skills/<skillName>/scripts/ 脚本目录代码签名 |
| 来源 | 内部需求（开发者提出） |
| 提出人 | zengsiyu3 |
| 目标发行版本 | TBD（随仓合入） |
| 候选 Profile | hapsigner |
| 优先级 | P2 |
| 状态 | Draft |

### 原始描述

> **原始问题（需求方原话）：**
> 我想要实现一个新功能，参考当前 native so 的实现逻辑，为 hap 包内新增的 scripts 文件夹下的脚本文件进行代码签名，如果可以，嵌入当前 native so 的实现方案也行，实现修改最小化，只涉及本仓修改。
>
> **补充（已与需求方确认）：**
> - "scripts 文件夹" 实际路径为 `skills/<skillName>/scripts/<file>`，位于 module.json 中 `skillProfiles` 数组声明的每个 skill 名称下
> - 复用现有 native SO 签名的实现机制（`NativeLibInfoSegment` / `SoInfoSegment`），不引入新的 segment 类型
> - 仅本仓修改，不涉及 OpenHarmony 其它仓

### 痛点

| 用户类型 | 当前痛点 | 影响 |
|----------|----------|------|
| 应用开发者 | HAP 包内 `<skillName>/scripts/` 下的脚本文件未纳入代码签名，存在被篡改后伪装成原包的风险 | 应用完整性保护缺失 |
| 系统开发者 | 缺乏统一的脚本签名机制，需手工校验脚本来源 | 系统安全性降低 |

### 期望结果

需求方希望：扩展现有代码签名工具（Java + C++ 两套实现），在 HAP 签名时自动对 `skills/<skillName>/scripts/` 下所有非目录文件执行与 native SO 一致的代码签名（fs-verity digest + 私钥签名），签名结果落入现有 `SoInfoSegment`。

### 背景证据

| 证据类型 | 链接/路径 | 说明 |
|----------|-----------|------|
| 现有实现 | `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp:226 SignNativeLibs` | 参考实现入口 |
| 现有实现 | `hapsigntool/hap_sign_tool_lib/.../CodeSigning.java:263 signNativeLibs` | 参考实现入口 |
| module.json schema | 仓内 `tools/profile.json` 样本 | 验证 skillProfiles 字段名 |

### 初始范围

**可能包含：**
- 在 `CodeSigning::GetCodeSignBlock` (C++) / `CodeSigning.getCodeSignBlock` (Java) 中新增"脚本签名"步骤
- 在 `HapUtils` (双端) 中新增"从 module.json 解析 skill 名称列表"工具方法
- 端到端单测覆盖新增代码路径

**明确不包含：**
- 不修改 verify 端的现有逻辑（签名写入 SoInfoSegment 即可被现有 verify 流程覆盖）
- 不新增 CLI 参数（脚本签名是默认行为，无开关）
- 不修改 module.json schema
- 不涉及 OpenHarmony 其它仓
- 不生成 Java/C++ 二进制等价性集成测试（用户决定本轮不做）

### 初始假设

| 假设 | 类型 | 验证方式 | 状态 |
|------|------|----------|------|
| module.json 中 skill 数组键名是 `skillProfiles` | 技术 | 与需求方确认（用户已确认） | 已验证 |
| `skills/<skillName>/scripts/` 下所有非目录文件均需签名 | 业务 | 与需求方确认（用户已确认） | 已验证 |
| 签名复用 `SoInfoSegment`（不新增 ScriptInfoSegment） | 技术 | 现有 native 实现参考 + 最小改动原则 | 已确认 |
| Java 与 C++ 端必须等价签名结果（hapsigner profile 硬约束） | 技术 | hapsigner profile 规则 | 已确认 |
| 现有 working tree 中的 6 文件修改是基线 | 技术 | git status 已确认 | 已验证 |

### 初始分级判断

| 判断项 | 结果 | 依据 |
|--------|------|------|
| 复杂度 | **简单** | 单仓小修；用户已确认；无跨仓；无新 CLI；复用现有 segment |
| 涉及仓数量 | 1 | `developtools/hapsigner` 本仓 |
| 是否涉及 Public/System API | 否 | 仅修改本仓内部代码，不暴露新 API |
| 是否涉及安全/性能关键路径 | 是（安全相关） | 涉及代码签名，但属于"扩展现有签名机制"，不引入新的密码学原语 |
| 是否跨 SIG | 否 | hapsigntool SIG 内部变更 |

### 进入澄清条件

- [x] 原始问题和期望结果已记录
- [x] 需求来源和责任人已明确（待用户最终确认）
- [x] 初始范围和不包含项已记录
- [x] 关键假设和待澄清问题已列出
- [x] 复杂度已判断（简单）

---

## 二、澄清记录

> 澄清是逐轮对话，不是一次性填表。先从"待澄清问题"出发，一次只讨论一个问题，结论确认后再写入本记录。
> 全部澄清完成后，向需求方输出总结确认。

### 待澄清问题

| 编号 | 问题 | 为什么需要澄清 | 状态 |
|------|------|----------------|------|
| Q-1 | Owner / 责任人是谁？ | 影响 manifest.owner 字段和后续审批人 | 已澄清 → `zengsiyu3` |
| Q-2 | 优先级 P0/P1/P2/P3？ | 影响 AC 详细程度和发布节奏 | 已澄清 → P2 |
| Q-3 | 目标发行版本是哪个？ | 影响 manifest.target_release 字段 | 已澄清 → TBD（随仓合入） |
| Q-4 | module.json 缺失/损坏怎么处理？ | 影响 AC-4 行为描述 | 已澄清 → 缺失 warn-and-continue；损坏抛异常 |
| Q-5 | scripts 目录下子目录递归扫描吗？ | 决定匹配规则（`startsWith` 是否包含 `skills/<skillName>/scripts/sub/x.y`） | 已澄清 → 不递归 |
| Q-6 | 工作树中 `.gitignore` 修改、`opencode.json` 等是否合入此 PR？ | 影响 commit 范围 | 已澄清 → 只交 scripts-signing 相关文件 |

### 讨论记录

| 日期 | 参与人 | 讨论主题 | 结论 | 后续动作 |
|------|--------|----------|------|----------|
| 2026-06-03 | 需求方 | JSON 键名对齐 | C++ 端改为 `skillProfiles` 与 Java 对齐 | 写入 T1 任务 |
| 2026-06-03 | 需求方 | 脚本文件范围 | 签 `skills/<skillName>/scripts/` 下所有非目录文件 | 写入 AC-1/AC-3 |
| 2026-06-03 | 需求方 | UTF-8 BOM | 恢复 `hap_utils.h/.cpp` 首行 BOM | 写入 T1 任务 |
| 2026-06-03 | 需求方 | 路径前缀 | 确认 `skills/<skillName>/scripts/<file>` | 写入 T2 任务 |
| 2026-06-03 | 需求方 | 复杂度 | 简单，跳过 design.md | 调整 spec 模板 |
| 2026-06-03 | 需求方 | Task 拆分 | 按实现范围拆 3 个（hap_utils / code_signing / tests） | Stage 3 任务划分 |
| 2026-06-03 | 需求方 | 集成等价性测试 | 本轮不做 | 范围排除 |
| 2026-06-03 | 需求方 | C++ 单测 | 写测试源码但手动构建 | T3 任务完成判据调整 |
| 2026-06-03 | 需求方 | `.gitignore` | 需求外，不动 | 排除 |
| 2026-06-03 | 需求方 | Q-1 Owner | `zengsiyu3` | 写入 manifest.owner |
| 2026-06-03 | 需求方 | Q-2 优先级 | P2 | 写入 proposal |
| 2026-06-03 | 需求方 | Q-3 目标发行版本 | TBD（随仓合入） | 写入 manifest.target_release |
| 2026-06-03 | 需求方 | Q-4 错误处理 | 缺失 warn-and-continue；损坏抛异常 | 写入 AC-4 |
| 2026-06-03 | 需求方 | Q-5 子目录递归 | 不递归 | 写入 AC-1/AC-3 |
| 2026-06-03 | 需求方 | Q-6 PR 提交范围 | 只交 scripts-signing 相关文件 | 写入范围边界 |

### 功能范围确认

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 核心功能包含哪些？ | 在 CodeSigning 中加入"脚本签名"步骤；HapUtils 加入 skill 名称解析 | 需求方 | 已确认 |
| 明确不包含哪些？ | verify 端改造、CLI 参数、module.json schema、跨仓变更、集成等价性测试 | 需求方 | 已确认 |
| 是否有分期策略？ | 否，一次性完成 | 需求方 | 已确认 |

### 子系统影响

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 涉及哪些子系统？ | developtools_hapsigner 子系统 | 需求方 | 已确认 |
| 是否需要新增子系统或部件？ | 否 | 需求方 | 已确认 |

### API 变更评估

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 是否需要新增/修改 Public API？ | 否 | 需求方 | 已确认 |
| 是否需要新增 System API？ | 否 | 需求方 | 已确认 |
| 是否会废弃已有 API？ | 否 | 需求方 | 已确认 |
| 是否需要新增权限声明？ | 否 | 需求方 | 已确认 |

### 兼容性与非功能需求

| 类别 | 核心问题 | 结论 | 确认人 | 状态 |
|------|----------|------|--------|------|
| 兼容性 | 现有 HAP 签名流程是否受影响？ | 仅当 HAP 含 `skillProfiles` 时新增 entry；否则与现行为完全一致（向后兼容） | 需求方 | 已确认 |
| 性能 | 多读一次 module.json 的开销？ | 优化为单次读取（T2 任务） | 需求方 | 已确认 |
| 安全 | 脚本签名与 native SO 同机制 | 复用 fs-verity + 私钥签名，无新密码学风险 | 需求方 | 已确认 |
| 可靠性 | module.json 缺失/损坏怎么办？ | 缺失：warn-and-continue；损坏：抛异常，终止签名流程 | 需求方 | 已确认 |

### 依赖与风险

| 依赖项 | 类型 | 说明 | 状态 |
|--------|------|------|------|
| cJSON 库 | 编译 | C++ 端解析 module.json 需 cJSON（仓内已包含） | 已确认 |
| minizip | 编译 | C++ 端读取 HAP 内容（仓内已包含） | 已确认 |
| gson | 编译 | Java 端 JSON 解析（仓内已包含） | 已确认 |

| 风险 | 类型 | 影响 | 缓解措施 | 状态 |
|------|------|------|----------|------|
| C++ 编译需用户手动验证 | 流程 | T1/T2/T3 完成判据依赖用户 | task.md 内显式记录 | 已确认 |
| 现有测试用例可能因签名流程新增 entry 而变化 | 兼容 | 已有 `code_signing_test` 可能需要更新断言 | 在 T1/T2 完成时回归 | 待确认 |
| 写错 JSON 键名导致 SoInfoSegment 内容双端不一致 | 兼容 | 违反 hapsigner profile 等价约束 | F1+F2 修复 + 单测覆盖 | 已识别 |

### AC 完整性

- [ ] 每个用户故事有验收标准
- [ ] AC 全部使用 WHEN/THEN 格式
- [ ] 覆盖正常流程、异常流程、边界条件
- [ ] AC 可测试、可度量

### 澄清结论

- [x] 功能范围已完全明确
- [x] 子系统影响已识别
- [x] API 变更已评估（N/A — 内部模块）
- [x] 兼容性和非功能需求已确认
- [x] 依赖和风险已识别且有缓解方案
- [ ] AC 完整可测试（待 Q-1~Q-6 落到具体 AC）
- [x] 标准及以上复杂度已完成方案探索（**N/A — 简单复杂度**）

**结论:** 条件通过（所有澄清问题已回答，待用户最终确认基线 + Stage 1 批准）

---

## 三、需求基线

> 澄清完成后固化。manifest.md 是事实源，此处为审批结论。
> **当前未固化**——等待所有 Q-1 ~ Q-6 澄清完成 + 用户明确批准。

### 基线信息

| 字段 | 内容 |
|------|------|
| 基线版本 | v1.0 |
| 基线日期 | 2026-06-03（待用户批准时确定） |
| Owner | zengsiyu3 |
| 确认人 | zengsiyu3（需求方兼 Owner） |
| 复杂度 | 简单 |
| Profile | hapsigner |
| 目标发行版本 | TBD（随仓合入） |
| 版本状态 | proposed |

### 问题陈述

HAP 包内 `skills/<skillName>/scripts/` 下的脚本文件当前未纳入代码签名，存在被篡改后伪装成原包的风险；本需求扩展现有代码签名工具（Java + C++ 双实现），在 HAP 签名时自动对这些脚本执行与 native SO 一致的代码签名（fs-verity digest + 私钥签名），结果落入现有 `SoInfoSegment`，最小化改动本仓。

### 目标和成功指标

| 目标 | 成功指标 | 验证方式 |
|------|----------|----------|
| 脚本签名覆盖完整 | 1 个 skill 下 N 个 scripts 文件 → SoInfoSegment 恰增 N 条 entry | 单元测试 + 集成测试 |
| 双实现等价 | Java 与 C++ 在相同输入 + 相同 profile 下 SoInfoSegment entry name 列表相同 | 本轮仅做静态代码 review + 单测覆盖（等价性集成测试不在范围内） |
| 向后兼容 | HAP 无 `skillProfiles` 时签名行为不变 | 单元测试 |
| 性能不退化 | module.json 单次读取 | 代码静态检查 + 不显著增加总体签名耗时 |

### 用户故事与 AC

| Story ID | 用户故事 | 优先级 |
|----------|----------|--------|
| US-1 | 作为 HAP 签名工具使用者，我想要在签名 HAP 时自动对 `skills/<skillName>/scripts/` 下所有非目录文件执行与 native SO 一致的代码签名 | P2 |

| AC编号 | 验收标准 | 类型 | 关联Story |
|--------|----------|------|-----------|
| AC-1 | WHEN HAP 的 module.json 含 N 个 `skillProfiles` 项，第 i 个 skill 名称下有 K_i 个 `scripts/` 直接子文件 THEN SoInfoSegment 恰增 ΣK_i 条 entry，entry name 格式为 `skills/<skillName>/scripts/<file>` | 正常 | US-1 |
| AC-2 | WHEN HAP 的 module.json 不含 `skillProfiles` 字段 THEN SoInfoSegment 不变（与无 skillProfiles 的现有行为一致，向后兼容） | 正常 | US-1 |
| AC-3 | WHEN `skills/<skillName>/scripts/` 下的某项是目录 THEN 跳过该项，不写入 SoInfoSegment | 边界 | US-1 |
| AC-4 | WHEN HAP 缺少 module.json / module.json 损坏 / JSON 解析失败 THEN 记录 warn 日志，跳过 scripts 签名，继续处理 native SO（warn-and-continue） | 异常 | US-1 |
| AC-5 | WHEN `skills/<skillName>/scripts/sub/x.js` 等嵌套子目录项存在 THEN 不被签名（不递归） | 边界 | US-1 |
| AC-6 | WHEN Java 端与 C++ 端签名同一 HAP THEN 双方 SoInfoSegment entry name 列表完全一致（双实现等价，hapsigner profile 硬约束） | 正常 | US-1 |

### 范围边界

**包含：**
- C++ 端：CodeSigning + HapUtils 修改 + 单元测试源码
- Java 端：CodeSigning + HapUtils 修改 + 单元测试
- working tree 中 6 个修改文件按"修复后"状态合入

**不包含：**
- verify 端逻辑修改
- CLI 参数新增
- module.json schema 修改
- 跨仓变更
- Java/C++ 二进制等价性集成测试（本轮不做）

### API 变更项清单

| API 名称 | 变更类型 | 开放范围 | 概要说明 |
|----------|----------|----------|----------|
| **N/A** | N/A | N/A | 本次变更不涉及 Public/System API；仅内部模块新增方法 |

### 不涉及项确认

| 维度 | 涉及？ | 依据 | 若涉及，进入哪个下游文档 |
|------|--------|------|--------------------------|
| 性能 | 是（轻微） | 多读一次 module.json（已优化为单次） | spec.md |
| 安全与权限 | 是 | 复用现有签名机制 | spec.md |
| 兼容性 | 是 | 向后兼容（HAP 无 skillProfiles 时行为不变） | spec.md |
| API/SDK | 否 | 内部模块新增，不暴露 | N/A |
| IPC/跨进程 | 否 | 签名工具是离线工具 | N/A |
| 构建与部件 | 否 | BUILD.gn / bundle.json 无需修改（已有 cJSON/minizip/gson 依赖） | N/A |
| 国际化/无障碍 | 否 | 工具内部，无用户可见字符串 | N/A |
| 数据迁移 | 否 | 无 | N/A |

### 变更控制

| 变更类型 | 触发条件 | 处理规则 |
|----------|----------|----------|
| 范围新增 | 新增用户故事或仓/模块 | 重新评估复杂度和设计影响 |
| AC 变更 | 修改可观察行为或错误码 | 重新审批基线和 Spec |
| API 变更 | 新增/修改 Public/System API | 触发设计审批 |
| 非功能指标变更 | 性能/安全/兼容性阈值变化 | 重新确认测试计划 |
| 目标版本变更 | 交付版本调整 | 更新 manifest.target_release |

### 进入设计/Spec 条件

- [x] 所有 P0/P1 用户故事有 AC（US-1 优先级 P2，6 条 AC 已写）
- [x] 每条 AC 可测试、可度量
- [x] 范围内/外已确认
- [x] `manifest.target_release` 已确认（TBD 随仓合入）
- [x] `manifest.profile` 已确认（hapsigner）
- [x] 涉及仓、模块、SIG 已识别（developtools_hapsigner，1 个仓）
- [x] 不涉及项已标记 N/A
- [x] 变更控制规则已确认

**基线结论:** 待用户最终确认 + Stage 1 gate 通过
