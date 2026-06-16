# Stage 4 — 发布阶段 Gate

> 阶段：发布 (Release)
> 需求 ID：FEAT-20260603-001
> Profile：hapsigner
> 复杂度：简单
> Gate 总结论：**Approved**（所有检查项已通过，用户已确认 C++ 端验证）

## 通用 Gate 项

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| 1 | 验证命令已运行且输出为 PASS | ✅ 通过 | Java 24/24 PASS（`mvn -pl hap_sign_tool_lib test`）；Python E2E 9/9 PASS；C++ gtest 4/4 用户手动验证通过 |
| 2 | 所有测试通过（含回归） | ✅ 通过 | Java 含 4 新增 + 20 既有（0 退化）；C++ 新增 4 TC；Python E2E 9 TC；既有 `code_signing_test` / `HapSignToolTest` 无影响 |
| 3 | 构建通过 | ✅ 通过 | Java `mvn -pl hap_sign_tool_lib install` + `mvn -pl hap_sign_tool -am package` 均 SUCCESS；C++ `gn gen && ninja` 用户手动确认通过 |
| 4 | 无阻塞级 Open Issues | ✅ 通过 | review.md §五 — 仅 2 项 follow-up（C++ gtest 仓内自动化 / Java↔C++ 二进制等价性测试），均明确接受 |
| 5 | 复盘记录完成 | 跳过 | 简单级不要求；review.md §六 已含审查摘要 |
| 6 | Profile 追加 Gate 已逐项检查并写入 `gates/release.md` | ✅ 通过 | 见下方 "Profile 追加 Gate（hapsigner）" |

## Profile 追加 Gate（hapsigner）

| # | 检查项 | 结果 | 证据 |
|---|--------|------|------|
| H-7 | Java 实现是否通过 `mvn package` 编译成功？单元测试是否全部通过？ | ✅ 通过 | `mvn -pl hap_sign_tool_lib install` SUCCESS；`mvn test` → 24/24 PASS |
| H-8 | C++ 实现是否完成手动编译验证？ | ✅ 通过 | 用户手动 `gn gen && ninja` 编译通过；用户报告 4 个编译错误已全部修复 |
| H-9 | Java 和 C++ 是否都有单元测试覆盖？ | ✅ 通过 | Java: `HapUtilsTest.java` 4 TC PASS；C++: `hap_utils_skill_test.cpp` 4 TC PASS（用户手动） |
| H-10 | 是否有集成测试验证功能等价？ | ⚠️ 用户明确本轮不做 | 用户在 Stage 1 澄清轮明确"集成等价性测试先不用生成"；记入 Open Issues |
| H-9-E2E | 是否有端到端测试覆盖 AC？ | ✅ 通过 | Python E2E 9/9 TC 覆盖 AC-1/AC-2/AC-3/AC-4/AC-5/AC-1+3 全场景 |

## AC 覆盖最终验证

| AC | 描述 | 验证方式 | 结果 |
|----|------|----------|------|
| AC-1 | N 个 skill × K_i 个 scripts → ΣK_i 条 entry，name = `skills/<skillName>/scripts/<file>` | Java 单测（间接）+ Python E2E TC-E-1, TC-E-2, TC-E-9 | ✅ PASS |
| AC-2 | 无 `skillProfiles` 字段 → SoInfoSegment 不变（向后兼容） | Java 单测 + Python E2E TC-E-5, TC-E-6 | ✅ PASS |
| AC-3 | 目录项被跳过 | Java 单测 + Python E2E TC-E-3（含 `emptydir/` 目录项） | ✅ PASS |
| AC-4 | 缺 module.json → warn-and-continue；损坏 → 抛异常终止 | Python E2E TC-E-8（rc=0）+ TC-E-7（rc=1） | ✅ PASS |
| AC-5 | 嵌套子目录不签名（不递归） | Python E2E TC-E-4（含 `sub/x.js` 嵌套文件） | ✅ PASS |
| AC-6 | Java/C++ 双端等价 | 静态代码 review + 双端单测 + Python E2E | ✅ PASS |

## 修复点最终核对（F1-F15）

| 编号 | 描述 | 文件 | 状态 |
|------|------|------|------|
| F1 | JSON 键名 `skills` → `skillProfiles` | `hapsigntool_cpp/hap/utils/src/hap_utils.cpp:137` | ✅ |
| F2 | 日志文本 `skills` → `skillProfiles` | `hapsigntool_cpp/hap/utils/src/hap_utils.cpp:139` | ✅ |
| F3 | UTF-8 BOM 恢复 | `hapsigntool_cpp/hap/utils/{include,src}` | ✅ |
| F4 | `SKILLS_PATH_PREFIX` 头文件声明 | `code_signing.h:45` | ✅ |
| F5 | `SKILLS_PATH_PREFIX = "skills/"` 定义 | `code_signing.cpp:33` | ✅ |
| F6 | `GetScriptEntriesFromHap` 签名变更 | `code_signing.h:69-71` + `code_signing.cpp:283-310` | ✅ |
| F7 | `SignSkillScripts` 调用更新 | `code_signing.cpp:268` | ✅ |
| F8 | `CheckFileNameForScripts` 路径拼接加 `skills/` | `code_signing.cpp:601-616` | ✅ |
| F9 | `CheckFileNameForScripts` 简化 + 嵌套判定 | `code_signing.cpp:601-616` | ✅ |
| F10 | Java `getScriptEntriesFromHap` 拆 3 守卫 | `CodeSigning.java:294-313` | ✅ |
| F10' | Java `SKILLS_PATH_PREFIX` 常量 | `CodeSigning.java:90` | ✅ |
| F11 | `CheckFileNameForScripts` 头文件声明 | `code_signing.h:91` | ✅ |
| F12 | `GetScriptEntriesFromHap` / `IterateScriptsEntries` 头文件声明 | `code_signing.h:69-73` | ✅ |
| F13 | soInfoList 合并改用 `combinedList` + `SetSoInfoList` | `code_signing.cpp:273-286` | ✅ |
| F14 | `getSkillNamesFromJson` catch 扩 `IllegalStateException` | `HapUtils.java:265` | ✅ |
| F15 | Python E2E 9 TC 脚本 | `tools/test/scripts_signing_e2e.py` | ✅ |

## 阶段流转

- 当前阶段：Stage 4 发布 ✅ Approved
- 终态：完成 — 等待用户 commit

## Approval 记录

| 阶段 | 决策 | 审批人 | 证据 | 下一阶段 |
|------|------|--------|------|----------|
| Stage 1 定义 | Approved | zengsiyu3 | 用户回复 "确认，批准 Stage 1 基线" | Stage 2 规格化 |
| Stage 2 规格化 | Approved | zengsiyu3 | 用户回复 "批准进入 Stage 3" | Stage 3 实现 |
| Stage 3 实现 | Approved | zengsiyu3 | 用户回复 "批准，按顺序执行"（含后续 revert + 文档重排） | Stage 4 发布 |
| Stage 4 发布 | Approved | zengsiyu3 | 用户回复 "代码验证通过，检视完成，进入 Stage 4" | 完成 |

## 最终复盘

- 实施时间：约 8 小时（跨多轮对话）
- 修复点：15 个（F1-F15），其中 2 个为用户已批准的中途策略调整（AC-4 重定义）
- 测试覆盖：Java 24 + C++ 4 + Python 9 = 37 个测试场景
- 工作树改动：2 新增 + 6 修改生产/测试文件 + 1 新增 E2E 脚本
- 用户手动验证：C++ `gn gen && ninja` 编译通过（4 个错误均已修复）
- 范围控制：未触碰 verify 端 / CLI / module.json schema / 跨仓变更
- 关键决策点：AC-4 行为在 Stage 3 中途根据用户澄清重新定义，3 个 warn-and-continue 修复点被判定为 bugfix 删除

## 后续行动（用户执行）

- [ ] 拆分 commit（建议 5 个）
- [ ] 合并到 dev 分支
- [ ] 关闭关联 Issue（如有）
