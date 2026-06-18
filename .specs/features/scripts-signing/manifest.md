---
id: FEAT-20260603-001
type: feature
title: "HAP 内 skills/<skillName>/scripts/ 脚本目录代码签名"
spec_schema: ohos-sdd/v1
profile: hapsigner
target_release:
  id: TBD
  status: proposed
  note: "随仓合入，未指定具体 OpenHarmony 发行版本"
complexity: simple
lineage: new-on-legacy
status: draft
owner: "zengsiyu3"
source_issue: ""
created_at: 2026-06-03
updated_at: 2026-06-10
related_features: []
related_bugs: []
related_tasks: []
related_decisions: []
code_refs:
  - hapsigntool_cpp/codesigning/sign/src/code_signing.cpp
  - hapsigntool_cpp/codesigning/sign/include/code_signing.h
  - hapsigntool_cpp/hap/utils/src/hap_utils.cpp
  - hapsigntool_cpp/hap/utils/include/hap_utils.h
  - hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/sign/CodeSigning.java
  - hapsigntool/hap_sign_tool_lib/src/main/java/com/ohos/hapsigntool/codesigning/utils/HapUtils.java
  - hapsigntool_cpp_test/unittest/codeSigning/utils/hap_utils_skill_test.cpp
  - hapsigntool/hap_sign_tool_lib/src/test/java/com/ohos/hapsigntool/codesigning/utils/HapUtilsTest.java
  - tools/test/scripts_signing_e2e.py
commits: []
baseline_approval:
  approved: true
  approver: "zengsiyu3"
  evidence: "用户回复 '确认，批准 Stage 1 基线'；参见 .specs/features/scripts-signing/proposal.md 讨论记录表"
  approved_at: "2026-06-03"
stage_gates:
  define: approved
  specify: approved
  implement: approved
  release: approved
---
