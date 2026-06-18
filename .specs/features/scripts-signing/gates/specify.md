# Stage 2 — 规格化阶段 Gate

> 阶段：规格化 (Specify)
> 需求 ID：FEAT-20260603-001
> Profile：hapsigner
> 复杂度：简单
> Gate 总结论：**待用户批准**（所有检查项已通过，等待用户审阅后明确批准）

## 通用 Gate 项

### 并行产出锚点

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| 1 | proposal.md 中 API 变更项清单已填写或标记 N/A | ✅ 通过（N/A） | `proposal.md` 三、API 变更项清单 — 标 N/A（仅内部模块新增方法） |
| 2 | design.md 和 spec.md 引用的仓/模块列表与 proposal.md 影响范围一致 | ✅ 通过（N/A） | 简单级跳过 design.md；spec.md 引用与 proposal.md 一致（1 仓 6 文件） |

### 设计检查（跳过条件：简单变更无多模块/新 API/分层决策）

> 简单级别跳过本节。理由：
> - 单仓修改
> - 无新 Public/System API
> - 无跨层调用问题（签名工具是离线工具）
> - 复用现有 NativeLibInfoSegment，不涉及分层决策

**跳过依据：**
- spec.md 技术约束段已承载关键架构决策（6 条硬约束）
- 架构决策属"复用 vs 新建"取舍，仅 1 个 ADR，spec.md 一段已足够

### 一致性检查

> 因 design.md 跳过，本节只检查 spec.md 内部一致 + spec.md 与 proposal.md 交叉一致。

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| 3 | 涉及仓和模块名称一致 | ✅ 通过 | spec.md 与 proposal.md 均引用 1 仓（`developtools/hapsigner`）+ 6 文件清单 |
| 4 | API 名称和变更类型一致 | ✅ 通过 | spec.md API 变更分析表与 proposal.md 一致（N/A） |
| 5 | 架构约束不矛盾 | ✅ 通过 | spec.md 技术约束 6 条与 proposal.md 兼容性与非功能需求表无冲突 |
| 6 | 不涉及项结论一致 | ✅ 通过 | spec.md 全局特性影响表与 proposal.md 不涉及项确认表一致 |

### Spec 检查

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| 7 | 用户故事和 AC 完整 | ✅ 通过 | spec.md 用户故事 1 个（US-1）+ 6 条 AC（AC-1~AC-6） |
| 8 | AC 覆盖正常/异常/边界 | ✅ 通过 | AC-1/AC-2 正常；AC-4 异常；AC-3/AC-5 边界 |
| 9 | Spec 中无 InnerKit 接口定义、内部实现流程或框架层实现细节 | ✅ 通过 | spec.md 只描述用户可见行为和验收标准；具体类名/方法名仅在"新增 API"表的"功能描述"列简要列举，作为追溯锚点 |
| 10 | API 变更分析完整（如有），含入参概要、返回值、错误码和开放范围 | ✅ 通过 | spec.md API 变更分析表完整，5 个新方法均列出 入参/返回值/错误码/开放范围 |
| 11 | 兼容性声明完整 | ✅ 通过 | spec.md 兼容性声明 — 5 维度（API 行为/配置格式/数据格式/最低版本/API 版本号）+ 向后兼容 |
| 12 | 非功能需求有指标或明确 N/A | ✅ 通过 | spec.md 非功能性需求表 — 性能/安全/可靠性/问题定位 4 项均已填或 N/A |
| 13 | 全局特性影响已筛选 | ✅ 通过 | spec.md 全局特性影响表 — 7 个特性均已评估（无障碍/大字体/深色模式/多窗口/多用户/版本升级/生态兼容） |
| 14 | 上下文引用完整 | ✅ 通过 | spec.md context-references + 关键文档列表 |
| 15 | Profile 追加 Gate 已逐项检查 | ✅ 通过 | 见下方 "Profile 追加 Gate（hapsigner）" |

## Profile 追加 Gate（hapsigner）

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| H-4 | Java 和 C++ 数据结构是否二进制等价？关键数据结构的字段定义、字节序、大小端必须一致 | ✅ 通过（N/A — 不引入新数据结构） | 本特性复用 `NativeLibInfoSegment`（已有二进制布局）；不新增 ScriptInfoSegment；spec.md 技术约束第 1 条明确"复用 SoInfoSegment" |
| H-5 | 错误码体系是否一致？同一错误场景应有相同的错误码 | ✅ 通过（N/A — 本特性不引入新错误码） | spec.md 异常/豁免规则表 — 3 类异常均不产生新错误码；统一以 WARN 日志 + 跳过策略处理；与现有 native SO 缺 libs/ 时的策略一致 |
| H-6 | 涉及模块变更时，是否确保两种实现的对应模块同步更新？ | ✅ 通过 | spec.md 增量表清晰列出 Java 端 4 处修改（CodeSigning 调用链 + HapUtils 新方法 + SCRIPTS_SUFFIX 常量）和 C++ 端 6 处修改（含 BOM 恢复、JSON 键名 fix）；执行计划 Stage 3 的 T1/T2 已按范围拆分 |

## 阶段流转

- 当前阶段：Stage 2 规格化 ✅ Approved
- 下一阶段：Stage 3 实现（pending）— execution-plan.md + tasks/T1, T2, T3 准备就绪后请求批准

## Approval 记录

| 阶段 | 决策 | 审批人 | 证据 | 下一阶段 | 重检范围 |
|------|------|--------|------|----------|----------|
| Stage 1 定义 | Approved | zengsiyu3 | 用户回复 "确认，批准 Stage 1 基线" | Stage 2 规格化 | N/A |
| Stage 2 规格化 | Approved | zengsiyu3 | 用户回复 "批准进入 Stage 3" | Stage 3 实现 | N/A |
