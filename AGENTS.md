# developtools_hapsigner 组件指引（OpenHarmony 应用与二进制签名工具）

> 本仓库面向 Agent 的指导文档统一使用中文；代码标识符、命令、路径、文件名保留原文。本仓为 OpenHarmony **应用包签名工具**与**二进制签名工具**的源码仓，属 `developtools` 子系统下 `hapsigner` 部件，提供密钥对生成、CSR 生成、证书生成、Profile 文件签名/验签、应用包（hap/hsp/hqf）签名/验签、二进制 ELF 文件签名/验签等功能。经签名的应用与二进制文件方可在真机设备安装、运行、调试；在支持强制代码签名的设备上，该机制提供运行时合法性校验与完整性保护。本仓包含**三套签名工具实现**，各有独立 Agent 指引文档，改动前请先按下方索引定位到对应子目录的 `AGENTS.md`。

## 子目录 Agent 指引索引

本仓按工具实现分为三个子目录，每个子目录下有独立的 `AGENTS.md`，包含该工具的完整代码结构、知识路由、约束边界与验证闭环。**改动任一工具前，先读对应子目录的 `AGENTS.md`。**

### [hapsigntool/AGENTS.md](hapsigntool/AGENTS.md) —— Java 版应用包签名工具

- **可执行目标**：`hap-sign-tool.jar`（Maven shade fat jar，主类 `com.ohos.hapsigntool.HapSignTool`）
- **语言/构建**：Java 8 + Maven3 多模块（`hap_sign_tool_lib` 核心库 + `hap_sign_tool` CLI 应用）
- **能力**：11 个 CLI 命令（`sign-app`/`verify-app`/`sign-profile`/`verify-profile`/`resign-enterprise-app`/`generate-keypair`/`generate-ca`/`generate-cert`/`generate-csr`/`generate-app-cert`/`generate-profile-cert`）+ 返回 `RetMsg` 的程序化静态 API；签名算法 `SHA256/384withECDSA`、`SHA256/384/512withRSA`/`RSA/PSS`
- **特点**：BouncyCastle 密码学、自定义 ZIP 读写（无第三方 zip 库）、fs-verity 代码签名、PKCS7/CMS、profile `.p7b` 签名
- **定位**：HAP/`so`/`bin` 全链路签名与验签的 **Java 入口**

### [hapsigntool_cpp/AGENTS.md](hapsigntool_cpp/AGENTS.md) —— C++ 版应用包签名工具

- **可执行目标**：`hap-sign-tool`（GN `ohos_executable`）
- **语言/构建**：C++17（`-fno-rtti`，无异常）+ GN/ohos-sdk 形态；OpenSSL shared + cJSON + zlib + c_utils
- **能力**：11 个 CLI 命令（与 Java 版对齐）；签名算法仅 `SHA256withECDSA`/`SHA384withECDSA`，密钥 `NIST-P-256`/`NIST-P-384`
- **特点**：HAP(zip)/ELF/Bin/Profile 全链路；自定义 `zip/` 读写、`codesigning/datastructure/` 多段代码签名块、`signer/` 抽象（本地+远程 so 插件）；**本目录是 `binary_sign_tool/` 的共享源码提供方**
- **定位**：HAP/ELF/Bin/Profile 全链路签名与验签的 **C++ 入口**，兼 `binary_sign_tool` 的源码基座

### [binary_sign_tool/AGENTS.md](binary_sign_tool/AGENTS.md) —— 原生 ELF 二进制签名工具

- **可执行目标**：`binary-sign-tool`（GN `ohos_executable`，ohos-sdk 形态）+ `binary-sign-tool.jar`（Java，Maven）
- **语言/构建**：C++17（`-fno-rtti`，无异常）+ GN/ohos-sdk（静态 OpenSSL）；另有 Java 子工程 `binary_sign_tool/java/`
- **能力**：2 个 CLI 命令（`sign`/`display-sign`）；仅 `SHA256withECDSA`/`SHA384withECDSA`；自签名（`-selfSign`）+ 证书签名；`-moduleFile` 权限
- **特点**：直接调 OpenSSL（PKCS7/X509/EVP/HMAC）；`elfio` 写真实 ELF section（`.codesign`/`.profile`/`.permission`，4K 对齐）；fs-verity Merkle 树；经各 `signature_tools_*.gni` 聚合复用 `hapsigntool_cpp/` 源文件并提供覆盖版（`sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp` 等）；新增 `compare_elf.cpp`/`self_sign_sign_provider.cpp`
- **定位**：**ELF 二进制签名专用入口**，`hapsigntool_cpp/` 的覆盖消费者

## 按任务定位工具

| 任务 | 适用工具 | 对应文档 |
| --- | --- | --- |
| HAP/HSP/HQF 应用包签名（zip 容器） | `hapsigntool`（Java）或 `hapsigntool_cpp`（C++） | 对应 `AGENTS.md` |
| Profile `.p7b` 签名/验签 | `hapsigntool`（Java）或 `hapsigntool_cpp`（C++） | 对应 `AGENTS.md` |
| 密钥对/CSR/证书生成 | `hapsigntool`（Java）或 `hapsigntool_cpp`（C++） | 对应 `AGENTS.md` |
| 二进制 ELF 文件签名（`sign`/`display-sign`） | `binary_sign_tool` | [binary_sign_tool/AGENTS.md](binary_sign_tool/AGENTS.md) |
| 企业应用重签名（`resign-enterprise-app`） | `hapsigntool`（Java）或 `hapsigntool_cpp`（C++） | 对应 `AGENTS.md` |
| 远程签名（so 插件 / JAR 插件） | `hapsigntool_cpp`（C++，CLI 可达）或 `hapsigntool`（Java） | 对应 `AGENTS.md` |
| 共享源码（`signer/`、`key_store_helper`、`localization_adapter` 等）改动 | `hapsigntool_cpp`（源码提供方）+ `binary_sign_tool`（覆盖消费者） | 两份 `AGENTS.md` 均需核对 |
| 签名格式常量（magic/block ID/fs-verity/OID）改动 | 三者均需同步 | 三份 `AGENTS.md` 均需核对 |

## 词汇路由

任务描述、日志、issue 或文件中若出现下列域词，先按下表命中场景定位再编辑（术语解释不内联于本文件，锚点指向子 `AGENTS.md` 或常量定义处）：

| 域词 / 缩写 | 命中场景 | 先读 |
| --- | --- | --- |
| `HAP Sig Block 42` / `<hap sign block>` / magic V2/V3 | HAP 签名块格式改动 | 对应 `AGENTS.md` 的"约束→三实现共享签名格式规范" + 子 `AGENTS.md` 的 HAP 块 magic 锚点 |
| block ID（`0x20000000`~`0x30000002`） | 签名块类型/权限块/代码签名块改动 | 对应子 `AGENTS.md` 的 `hap_utils`/`HapUtils` block ID 锚点 |
| `fs-verity` / Merkle 树 / `FS_SHA256`/`FS_SHA512` / 4K 对齐 | 代码签名块或 ELF `.codesign` 改动 | 对应子 `AGENTS.md` 的 fs-verity 章节锚点 |
| `ownerID OID`（`1.3.6.1.4.1.2011.2.376.1.4.1`） | 签名归属/验签匹配改动 | 触发三向核对（见"约束"） |
| `Profile` / `.p7b` / `Provision` | profile 签名/验签改动 | 对应工具子 `AGENTS.md` 的 profile 章节 |
| `RetMsg` / `ServiceApi`（C++ 纯虚基类） | 程序化静态 API 改动 | `hapsigntool/AGENTS.md` 或 `hapsigntool_cpp/AGENTS.md` 的 Ask before API 条目 |
| `signerPlugin` / `RemoteSigner` / `signer.properties` | 远程签名器插件改动 | 对应子 `AGENTS.md` 的 signer 章节 |
| `PasswordGuard`（C++）/ `EnterPassword`（Java）/ `pwdInputMode` | 口令采集改动 | 对应子 `AGENTS.md` 的安全关键约束 |
| `realpath` / `PATH_MAX` / `FileUtils.validFileType` | 路径校验改动 | 对应子 `AGENTS.md` 的安全关键约束 |
| `sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp` 等覆盖版 | 共享源码改动 | 两份 `AGENTS.md` 双向核对（见下"高频/高风险改动路径"） |

## 仓库总览

```
developtools_hapsigner_4G
├── autosign/                # 一键签名脚本（Python3.5+）
├── binary_sign_tool/        # 原生 ELF 二进制签名工具（C++17 + Java）
│   └── AGENTS.md            # ← binary_sign_tool Agent 指引
├── dist/                    # SDK 预置文件（OpenHarmony.p12/.pem/.p7b/.json 模板）
├── figures/                 # README 用图
├── hapsigntool/             # Java 版应用包签名工具
│   ├── hap_sign_tool/       #   CLI 应用模块
│   ├── hap_sign_tool_lib/  #   核心签名库
│   └── AGENTS.md            # ← hapsigntool Agent 指引
├── hapsigntool_cpp/         # C++ 版应用包签名工具（兼 binary_sign_tool 源码基座）
│   └── AGENTS.md            # ← hapsigntool_cpp Agent 指引
├── hapsigntool_cpp_test/    # C++ 版工具的 gtest 单测 + fuzz 测试
├── tools/                   # 自动化测试脚本/资源
├── README.md / README_ZH.md # 仓库 README（人类阅读）
├── BUILD.gn                 # 顶层构建入口
└── bundle.json              # 部件元数据
```

### 高频/高风险改动路径

下列路径改动影响跨工具一致性或设备端验签，编辑前先读对应 `AGENTS.md` 并按"约束"做双向/三向核对：

| 路径 | 风险点 | 同步要求 |
| --- | --- | --- |
| `hapsigntool_cpp/signer/`、`common/`、`utils/key_store_helper`、`localization_adapter` | 100% 被 `binary_sign_tool` 复用 | 改共享语义须同步 `binary_sign_tool/` |
| `hapsigntool_cpp/hap/sign/sign_elf.cpp`、`codesigning/sign/code_signing.cpp`、`codesigning/fsverity/fs_verity_generator.cpp`/`merkle_tree_builder.cpp`、`hap/sign/bc_pkcs7_generator.cpp`、`profile/profile_sign_tool.cpp`、`profile/profile_info.cpp`、`common/options.cpp`、`utils/file_utils.cpp` | `binary_sign_tool` 提供覆盖版 | 改本目录版须同步覆盖版 |
| HAP 块 magic/ID、fs-verity 常量、ownerID OID、签名能力字节数组 | 设备端验签强依赖 | Java/C++/`binary_sign_tool` 三处字节兼容 |
| `hapsigntool/hap/utils/HapUtils.java`、`hapsigntool_cpp/hap/utils/include/hap_utils.h` | block ID/magic/版本常量 | 三实现共享格式 |
| `hapsigntool` 的 `help.txt` / `hapsigntool_cpp` 的 `help.h` | 合法参数白名单由其派生 | 改 help 即改 CLI 接受能力 |

## 约束（仓库级）

- **三实现共享签名格式规范**：HAP 签名块 magic（V2 `"HAP Sig Block 42"`/V3 `"<hap sign block>"`）、block ID（`0x20000000`~`0x30000002`）、fs-verity 常量（页大小 4K、`CODE_SIGN_VERSION`、`FS_SHA256/512`）、PKCS7/CMS 结构、ownerID OID（`1.3.6.1.4.1.2011.2.376.1.4.1`）在 Java 版、C++ 版、`binary_sign_tool` 中**须字节兼容**。改格式须三处同步。
- **双库复用**：`binary_sign_tool/` 经 `.gni` 聚合复用 `hapsigntool_cpp/` 的 signer/common/utils/cmd/codesigning/profile/hap 部分源文件，并对其中部分提供覆盖版；改共享语义须同步两套实现。
- **Java 8 字节码固定**（`hapsigntool`）：不得使用 Java 9+ 特性。
- **C++17 + `-fno-rtti`、无异常**（`hapsigntool_cpp`/`binary_sign_tool`）：用 `do{}while(0)`+`goto err` 清理。
- **口令安全**：Java 版存 `char[]` 经 `Console` 30s 超时；C++ 版经 `PasswordGuard` 无回显 `termios`+30s `poll`，`memset_s` 清零。不得日志输出明文口令/私钥/keystore。
- **路径校验**：不得绕过 `realpath`+`PATH_MAX`+父目录存在性校验（C++）/`FileUtils.validFileType`+`isValidFile`（Java）直接信任用户路径。
- **公共/静态 API（ask before）**：变更 `hapsigntool` 的 `RetMsg` 程序化静态 API（`signApp`/`verifyApp`/`signProfile`/`verifyProfile`/`reSignEnterpriseApp`）或 `hapsigntool_cpp` 的 `ServiceApi` 抽象基类（11 纯虚方法）签名/返回码前须确认，保持向后兼容；细节见对应子 `AGENTS.md` 的 Ask before 条目。
- **第三方依赖与 license**：升级 BouncyCastle/OpenSSL/elfio/cJSON/zlib 等须核对 license 兼容性与字节兼容性，不得静默升版；Java 版版本经父 `pom.xml` 的 `dependencyManagement` 锁定，C++ 版经 `bundle.json`/`BUILD.gn` 的 `external_deps` 声明。

## 构建和验证

- **Java 版**（`hapsigntool/`、`binary_sign_tool/java/`）：`mvn -s settings.xml clean package`（Maven3，Java 8）→ 产物 `hap-sign-tool.jar` / `binary-sign-tool.jar`
- **C++ 版**（`hapsigntool_cpp/`、`binary_sign_tool/`）：`./build.sh --product-name ohos-sdk`（在 OpenHarmony 源码根目录执行）→ 产物 `/openharmony_master/out/sdk/packages/ohos-sdk`
- **测试**：Java 版用 JUnit5（`mvn -s settings.xml test`）；C++ 版用 gtest（`hapsigntool_cpp_test/`，`--gtest_filter=`）
- **静态检查/lint**：Java 版 `-Xlint:all` 已编入编译（父 `pom.xml`），`mvn -s settings.xml -DskipTests=true clean package` 可观察编译告警；C++ 版经 OpenHarmony 构建链集成 `clang-tidy`/`cppcheck`（见子目录 `AGENTS.md`）。Java/C++ 均不得引入新增告警/告警级别抬升。

若无法运行验证（如缺 OpenHarmony 源码树、缺真实 keystore/`.p12` 证书链、缺远程签名器插件、缺板侧 fs-verity 内核能力），须说明缺失环境与未验证项，列出推荐验证步骤与预期输出关键字供人工执行，不得声称已验证。详细构建/测试/完成标准见各子目录 `AGENTS.md`。

### 仓库级最小完成标准

任务跨工具或触及共享格式时，完成须满足：

1. **代码改动已完成** - `git commit -s`
2. **相关工具构建通过** - 涉及的工具按上述命令编译成功（Java 版 `mvn -s settings.xml clean package`；C++ 版 `./build.sh --product-name ohos-sdk`）
3. **相关测试通过** - 受影响的测试套件执行并提供输出摘要（任务→测试映射见对应子目录 `AGENTS.md` 的"任务级验证映射"表）
4. **共享源码双向/三向核对** - 改 `hapsigntool_cpp/` 共享源时同步 `binary_sign_tool/` 覆盖版；改签名格式常量（magic/block ID/fs-verity/OID）时三处（Java/C++/binary_sign_tool）同步
5. **安全清单逐条核对** - 口令不得入日志、路径须 `realpath`/`FileUtils` 校验（详见各子目录"安全关键约束"）

> 完成报告格式、无法验证时的 fallback、任务级验证映射详见各子目录 `AGENTS.md` 的"构建和验证"章节。

## 开始编辑前

1. 确认任务涉及哪个工具（按上方"按任务定位工具"表），读对应子目录 `AGENTS.md`
2. 涉及共享源码或签名格式常量时，按对应 `AGENTS.md` 的"双库复用模型"说明，双向/三向核对
3. 声明："修改目标：X 工具的 Y；已读锚点：`<子目录>/AGENTS.md` 的 Z；遵循其约束"
