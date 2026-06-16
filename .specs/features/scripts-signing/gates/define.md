# Stage 1 — 定义阶段 Gate

> 阶段：定义 (Define)
> 需求 ID：FEAT-20260603-001
> Profile：hapsigner
> 复杂度：简单
> Gate 总结论：**通过 / Approved**

## 通用 Gate 项

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| 1 | 原始问题和期望结果已记录 | ✅ 通过 | `proposal.md` 一、原始需求 — 含原始描述、痛点、期望结果 |
| 2 | 需求来源和责任人已明确 | ✅ 通过 | `proposal.md` 一、基本信息 — 提出人=zengsiyu3，Owner=zengsiyu3 |
| 3 | 待澄清问题已逐项关闭 | ✅ 通过 | `proposal.md` 二、待澄清问题 — Q-1~Q-6 全部已澄清 |
| 4 | 讨论记录包含明确确认证据 | ✅ 通过 | `proposal.md` 二、讨论记录 — 含 15 行逐项决策；用户已确认基线 |
| 5 | 澄清结论全部适用项已勾选 | ✅ 通过 | `proposal.md` 二、澄清结论 — 6/7 勾选（AC 完整可测试勾选延后到 Stage 2） |
| 6 | 功能范围（包含/不包含）已确认 | ✅ 通过 | `proposal.md` 三、范围边界 — 含/不含均明确 |
| 7 | API 变更已评估 | ✅ 通过（N/A） | `proposal.md` 三、API 变更项清单 — 标 N/A，仅内部模块新增 |
| 8 | 兼容性和非功能需求已确认 | ✅ 通过 | `proposal.md` 二、兼容性与非功能需求 — 4/4 已确认 |
| 9 | 依赖和风险已识别并有缓解方案 | ✅ 通过 | `proposal.md` 二、依赖与风险 — 3 项依赖 + 3 项风险已识别 |
| 10 | 所有 P0/P1 用户故事有 AC（WHEN/THEN） | ✅ 通过 | `proposal.md` 三、用户故事与 AC — US-1 P2 已写 6 条 AC |
| 11 | 每条 AC 可测试、可度量 | ✅ 通过 | AC-1~AC-6 均为可静态/动态验证的判定式描述 |
| 12 | `manifest.target_release` 已确认 | ✅ 通过（TBD） | manifest.md `target_release.id = TBD`，note 注明随仓合入 |
| 13 | `manifest.profile` 已确认 | ✅ 通过 | manifest.md `profile = hapsigner` |
| 14 | 不涉及项已显式标记 N/A | ✅ 通过 | `proposal.md` 三、不涉及项确认 — 8 个维度均已标注 |
| 15 | `manifest.baseline_approval.approved=true` | ✅ 通过 | manifest.md `baseline_approval.approved = true`，approver=zengsiyu3，evidence 非空 |
| 16 | 总结论为 `通过/Approved` | ✅ 通过 | 本文件 Gate 总结论 |
| 17 | Profile 追加 Gate 已逐项检查 | ✅ 通过 | 见下方 "Profile 追加 Gate（hapsigner）" |

## Profile 追加 Gate（hapsigner）

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| H-1 | 新功能是否需要 Java 和 C++ 两套实现？若仅需一套，明确说明原因 | ✅ 通过 | 需要双实现：Java 与 C++ 是 hapsigner 的两套独立工具，均需支持脚本签名 |
| H-2 | 功能等价性验收标准是否明确？必须定义"什么算等价" | ✅ 通过 | AC-6 明确："Java 端与 C++ 端签名同一 HAP → 双方 SoInfoSegment entry name 列表完全一致"；定义等价=entry name 列表相同 |
| H-3 | 涉及文件格式变更时，是否确认两种实现都支持该格式？ | ✅ 通过（N/A） | 本次不涉及文件格式变更，仅扩展现有签名机制；N/A 已标注 |

## 阶段流转

- 当前阶段：Stage 1 定义 ✅ Approved
- 下一阶段：Stage 2 规格化（pending）— 需用户明确批准"进入 Stage 2"后开始

## Approval 记录

| 阶段 | 决策 | 审批人 | 证据 | 下一阶段 | 重检范围 |
|------|------|--------|------|----------|----------|
| Stage 1 定义 | Approved | zengsiyu3 | 用户回复 "确认，批准 Stage 1 基线" | Stage 2 规格化 | N/A |
