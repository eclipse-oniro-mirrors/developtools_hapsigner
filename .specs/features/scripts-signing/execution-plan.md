# 执行计划

> 将 Approved Spec 拆成可独立执行、可验证、可审查的 Task。

## Plan 元数据

| 字段 | 内容 |
|------|------|
| Plan ID | PLAN-20260603-001 |
| 关联 Feature | FEAT-20260603-001 |
| 关联文档 | `.specs/features/scripts-signing/proposal.md` (Approved) / `.specs/features/scripts-signing/spec.md` (Approved) |
| 复杂度 | 简单 |
| 状态 | Approved |
| Owner | zengsiyu3 |

## 输入状态

| 输入 | 路径 | 要求状态 |
|------|------|----------|
| Requirement | `.specs/features/scripts-signing/proposal.md` | Approved ✅ |
| Design | （跳过 — 简单级） | N/A |
| Spec | `.specs/features/scripts-signing/spec.md` | Approved ✅ |

## 修复点清单（按实现范围 + 时间顺序）

| 编号 | 描述 | 文件 | 阶段 | 关联 AC |
|------|------|------|------|---------|
| F1 | JSON 键名 `skills` → `skillProfiles` | `hapsigntool_cpp/hap/utils/src/hap_utils.cpp:137` | T1 | AC-1, AC-6 |
| F2 | 日志文本 `skills` → `skillProfiles` | `hapsigntool_cpp/hap/utils/src/hap_utils.cpp:139` | T1 | AC-1 |
| F3 | UTF-8 BOM 恢复 | `hapsigntool_cpp/hap/utils/{include,src}` | T1 | — |
| F4 | `SKILLS_PATH_PREFIX` 常量声明 | `hapsigntool_cpp/codesigning/sign/include/code_signing.h:45` | T2 | AC-1, AC-5, AC-6 |
| F5 | `SCRIPTS_SUFFIX` 常量值 | `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp:33` | T2 | AC-1 |
| F6 | `GetScriptEntriesFromHap` 签名变更（接收 `skillNames` 参数） | `hapsigntool_cpp/codesigning/sign/include/code_signing.h:69-71` + `src/code_signing.cpp:283-310` | T2 | AC-1, AC-5 |
| F7 | `SignSkillScripts` 调用更新（传递 `skillNames`） | `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp:268` | T2 | AC-1 |
| F8 | `CheckFileNameForScripts` 简化 + 加嵌套判定（替代原有"任何以 scriptsPath 开头都签"） | `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp:601-616` | T2 | AC-5 |
| F9 | Java `getScriptEntriesFromHap` 拆 3 守卫（isDirectory / startsWith / contains `/`） | `hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/sign/CodeSigning.java:294-313` | T2 | AC-5 |
| F10 | Java `SKILLS_PATH_PREFIX` 常量添加 | `hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/sign/CodeSigning.java:90` | T2 | AC-1, AC-5, AC-6 |
| F11 | `CheckFileNameForScripts` 头文件声明 | `hapsigntool_cpp/codesigning/sign/include/code_signing.h:91` | T2 | AC-5 |
| F12 | `GetScriptEntriesFromHap` / `IterateScriptsEntries` 头文件声明 | `hapsigntool_cpp/codesigning/sign/include/code_signing.h:69-73` | T2 | AC-1, AC-5 |
| F13 | soInfoList 合并改用 `combinedList` + `SetSoInfoList` | `hapsigntool_cpp/codesigning/sign/src/code_signing.cpp:273-286` | T2 | AC-1 |
| F14 | `getSkillNamesFromJson` catch 扩 `IllegalStateException` | `hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/utils/HapUtils.java:265` | T3 | AC-1, AC-2, AC-4 |
| F15 | Python E2E 9 TC 脚本 | `tools/test/scripts_signing_e2e.py` | T3 | AC-1 ~ AC-5 |

## AC 到 Task 追溯

| AC | 来源 | Task | 验证方式 | 覆盖？ |
|----|------|------|----------|--------|
| AC-1 | spec.md | T2, T3 | Java 单测 + C++ 单测（手动）+ 代码 review + Python E2E (TC-E-1, TC-E-2, TC-E-9) | ✅ |
| AC-2 | spec.md | T1, T2, T3 | Java 单测 + C++ 单测（手动）+ Python E2E (TC-E-5, TC-E-6) | ✅ |
| AC-3 | spec.md | T2, T3 | Java 单测 + C++ 单测（手动）+ Python E2E (TC-E-3) | ✅ |
| AC-4 | spec.md | T2, T3 | Python E2E (TC-E-7 损坏 sign rc=1; TC-E-8 缺失 sign rc=0) | ✅ |
| AC-5 | spec.md | T2, T3 | Java 单测 + C++ 单测（手动）+ Python E2E (TC-E-4) | ✅ |
| AC-6 | spec.md | T1, T2, T3 | 静态代码 review（JSON 键名、路径前缀、EntryCollection 顺序） + 双端单测 | ✅ |

## 首批实现边界

**首批必须实现：** 修复 working tree 中 6 文件的 bug（JSON 键名、BOM、路径前缀、模块 JSON 单次读取）+ 双端单测 + Python E2E

**可后置：** Java/C++ 二进制等价性集成测试（用户已明确本轮不做）

**不建议延后：** 路径前缀修复（与签名结果二进制布局直接相关）

## 阶段计划

| 阶段 | 目标 | 关键 Task | 结束门槛 | 最小验证 |
|------|------|-----------|----------|----------|
| Phase-1 | 修复 hap_utils 模块 | T1 | C++ 编译通过；JSON 键名 = `skillProfiles`；BOM 恢复 | 用户手动 `gn gen && ninja` 通过 |
| Phase-2 | 修复 code_signing 流程 | T2 | C++ + Java 编译通过；路径前缀 = `skills/`；module.json 单次读取 | 用户手动 `gn gen && ninja` 通过 + `mvn package` 通过 |
| Phase-3 | 新增双端单元测试 + Python E2E | T3 | Java 单测 24/24；C++ 测试源码合入 + 用户手动构建运行 PASS；Python E2E 9/9 | `mvn test` + `python3 tools/test/scripts_signing_e2e.py` + 用户手动 gtest |

## Task 粒度原则

- 简单级：3 张 Task Card（按实现范围划分）
- T1：纯 hap_utils 修复（F1-F3）— 1 个能力闭环
- T2：code_signing 流程修复（F4-F13）— 1 个能力闭环
- T3：测试新增（F14-F15；Java + C++ 单测 + Python E2E）— 1 个能力闭环

## 禁止项

执行计划和 Task 不得出现以下内容：

- [x] 没有 TBD / TODO / 占位符
- [x] 没有"根据需要实现""酌情处理"等模糊指令
- [x] 没有跨 Task 隐式依赖（依赖已显式声明在前置依赖列）
- [x] 没有要求 Agent 自行寻找未列出的上下文文件
- [x] 没有无验证方式的 AC
- [x] 没有"与 Task-N 类似""参考 Task-N 实现"等引用（每个 Task 自包含）

## Task 列表

| Task ID | 目标 | 文件范围 | 修复点 | 前置依赖 | 完成判据 | 验证命令 |
|---------|------|----------|--------|----------|----------|----------|
| T1 | 修复 hap_utils | `hapsigntool_cpp/hap/utils/{include,src}` | F1, F2, F3 | 无 | grep 验证键名；xxd 验证 BOM | 用户手动 `gn gen && ninja` |
| T2 | 修复 code_signing 流程 | `hapsigntool_cpp/codesigning/sign/{include,src}` + `hapsigntool/.../CodeSigning.java` | F4, F5, F6, F7, F8, F9, F10, F11, F12, F13 | T1 | C++ 编译；mvn 编译；现有 `code_signing_test` 不退化 | `gn gen && ninja` + `mvn package` |
| T3 | 新增双端单元测试 + Python E2E | `hapsigntool_cpp_test/.../utils/hap_utils_skill_test.cpp` + `hapsigntool/.../HapUtilsTest.java` + `tools/test/scripts_signing_e2e.py` | F14, F15 | T1, T2 | Java `mvn test` 24/24；C++ 源码合入 + 用户手动 gtest；Python E2E 9/9 | `mvn test` + `python3 tools/test/scripts_signing_e2e.py` + 用户手动 gtest |

## Plan 自审清单

- [x] 每个 P0/P1 AC 至少映射到一个 Task
- [x] 每个 Task 文件范围明确
- [x] 每个 Task 明确前置依赖、非目标、完成判据和停止条件
- [x] 每个 Task 有验证命令
- [x] Task 粒度形成能力闭环
- [x] 没有 TBD/TODO/占位符
- [x] 没有要求 Agent 自行寻找未列出的上下文
- [x] 交接信息自包含
- [x] 每个 Task 验证在完成时立即执行并记录证据
- [x] 简单级 3 Task，未超 3000 行阈值
