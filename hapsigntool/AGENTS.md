# hapsigntool 组件指引（OpenHarmony hapsigner / hap-sign-tool）

> 本仓库面向 Agent 的指导文档统一使用中文；代码标识符、命令、路径、文件名保留原文。本工具为 Java 8 主机侧 HAP/Profile 签名工具（可执行目标 `hap-sign-tool.jar`），为 HAP/`so`/`bin` 等产物提供 PKCS7/CMS 签名、fs-verity 代码签名块、profile `.p7b` 签名与全链路验签；签名后方可在真机设备运行/调试。属 `developtools` 子系统下 `hapsigner` 部件，Maven 多模块工程，主类 `com.ohos.hapsigntool.HapSignTool`。密码学依赖 BouncyCastle（`bcpkix-jdk18on` 1.82，静态注册于 `SignToolServiceImpl.java:75`），自定义 ZIP 读写（无外部 zip 库），日志基于 `java.util.logging` 经 `LogUtils` 封装。共 11 个 CLI 命令（`sign-app`/`verify-app`/`sign-profile`/`verify-profile`/`resign-enterprise-app`/`generate-keypair`/`generate-ca`/`generate-cert`/`generate-csr`/`generate-app-cert`/`generate-profile-cert`）；同时提供返回 `RetMsg` 的程序化静态 API（`signApp`/`verifyApp`/`signProfile`/`verifyProfile`/`reSignEnterpriseApp`）。签名算法支持 `SHA256/384withECDSA`、`SHA256/384/512withRSA`/`RSA/PSS` 等；密钥算法 `RSA`/`ECC`，密钥长度 `RSA{2048,3072,4096}`、`ECC{NIST-P-256,NIST-P-384}`。支持交互式口令输入（`pwdInputMode=1`，`Console` 30 秒超时）；密钥库接受 `p12`/`jks`。

## 项目定位

本目录是 hapsigner 的**Java 版 HAP/Profile 签名入口**，与 C++ 版 `hapsigntool_cpp/`、原生 ELF 二进制签名 `binary_sign_tool/` 并列。三者共享签名格式规范（HAP 签名块 magic、block ID、fs-verity 常量、PKCS7/CMS 结构、ownerID OID）但无代码依赖。本目录为 Maven 多模块工程，`hap_sign_tool_lib/` 是核心库，`hap_sign_tool/` 是 CLI 应用（依赖前者，经 shade 插件打成 fat jar）。

优先按这些目录定位问题：

- `hap_sign_tool/`：CLI 应用模块。`HapSignTool.java`（`main()` 在 `:115`，命令分发 `processCmd` 在 `:137`、`dispatchParams` 在 `:190`、`callGenerators` 在 `:161`）是进程入口与全命令分发中心；`hapsigntoolcmd/CmdUtil.java` 做 `-key value` 解析与受信参数校验；`hapsigntoolcmd/ParamsTrustlist.java` 由 `help.txt` 派生每命令合法参数白名单；`hapsigntoolcmd/HelpDocument.java` 渲染帮助文本；`com.ohos.entity/` 下为程序化 API 的参数 POJO（`SignAppParameters`/`VerifyAppParameters`/`SignProfileParameters`/`VerifyProfileParameters`/`ReSignEnterpriseAppParameters`、`Mode`/`InForm`/`SignCode` 枚举、`RetMsg`）。`src/main/resources/help.txt`（243 行）为完整 CLI 用法说明，`log.properties` 配日志级别。
- `hap_sign_tool_lib/api/`：服务门面。`ServiceApi.java`（接口，11 个方法声明）+ `SignToolServiceImpl.java`（437 行，实现 + BouncyCastle 静态注册 `:75`）+ `CertTools.java`（CSR/证书生成）。`SignToolServiceImpl` 按 `mode` 选 `LocalJKSSignProvider`/`RemoteSignProvider`，按 `inForm`(`zip`/`elf`/`bin`) 分发签名；验签分发 `VerifyHap`/`VerifyElf`。
- `hap_sign_tool_lib/hap/provider/`：签名 Provider 抽象。`SignProvider.java`（抽象基类，~1141 行，HAP 签名总编排：拷贝对齐 ZIP → 追加签名块 → 追加权限块 → `doSign` → 输出），`LocalJKSSignProvider.java`（JKS/PKCS12 + CRL），`RemoteSignProvider.java`（远程签名）。
- `hap_sign_tool_lib/hap/sign/`：HAP/ELF/Bin 签名器。`SignHap.java`（HAP 签名块构建 + 摘要计算）、`SignElf.java`/`SignBin.java`、`BcPkcs7Generator.java`（PKCS7/CMS signedData 打包 + 自验签）。
- `hap_sign_tool_lib/hap/verify/`：验签。`VerifyHap.java`（HAP ZIP 验签 + 企业重签验签 + 权限块验签）、`VerifyElf.java`、`VerifyAndParseProvision.java`、`X509CertificateSelector.java`。
- `hap_sign_tool_lib/codesigning/`：fs-verity 代码签名。`sign/CodeSigning.java`（组装 `CodeSignBlock`：HAP 路径用 `HapInfoSegment`+`FsVerityInfoSegment`+`NativeLibInfoSegment`，ELF 路径用 `ElfSignBlock`+`FsVerityDescriptorWithSign`）、`sign/BcSignedDataGenerator.java`（带 ownerID OID 的 CMS）、`fsverity/`（`FsVerityGenerator`/`MerkleTreeBuilder`/`FsVerityDescriptor`）、`datastructure/`（二进制结构体）、`elf/`（ELF 解析）、`utils/`（4K 对齐、app-identifier 提取）。
- `hap_sign_tool_lib/profile/`：profile `.p7b`。`ProfileSignTool.java`（`generateP7b`/`signProfile`，PKCS7 signedData DER 编码 + 自验签）、`VerifyHelper.java`、`IProvisionVerifier.java`；`profile/model/`（`Provision`/`BundleInfo`/`Acls`/`Permissions`/`Validity`/`VerificationResult` JSON 模型）。
- `hap_sign_tool_lib/signer/`：签名器抽象。`ISigner.java`（接口）、`LocalSigner.java`（`java.security.Signature`）、`RemoteSigner.java`（**stub，抛 `UnsupportedOperationException`**）、`SignerFactory.java`（经 `URLClassLoader` 加载远程签名器插件 JAR，读 `signer.properties`）。
- `hap_sign_tool_lib/zip/`：自定义 ZIP 读写（`Zip`/`ZipUtils`/`CentralDirectory`/`EndOfCentralDirectory`/`Zip64Eocd`/`Zip64EocdLocator`/`DataDescriptor`/`RandomAccessFileZipDataInput/Output`/`MessageDigestZipDataOutput`）。**签名直接操作 ZIP 容器，无第三方 zip 库依赖**。
- `hap_sign_tool_lib/utils/`：`KeyStoreHelper.java`（PKCS12/JKS 创建/校验/读取，100 年自签证书）、`CertUtils`/`CertificateUtils`/`CertChainUtils`（证书解析/验证/链）、`FileUtils`（文件校验/类型/后缀）、`EnterPassword.java`（交互式口令 30s 超时）、`LogUtils.java`/`LogFormatter.java`、`ValidateUtils`/`StringUtils`/`ByteArrayUtils`/`ParamProcessUtil`。
- `hap_sign_tool_lib/error/`：`ERROR.java`（枚举 0-119）、`CustomException.java`（`RuntimeException`，工厂 `throwException`）、`ErrorMsg.java`（builder，子系统 `110`=sign-tool/`111`=code-sign）、`SignToolErrMsg.java`（503 行消息常量）。
- `hap_sign_tool_lib/entity/`：`Options.java`（继承 `HashMap<String,Object>`，全部 CLI 键常量）、`ParamConstants.java`（签名参数常量 + legacy 错误码 `20001-20004`）、`SignatureAlgorithm`/`ContentDigestAlgorithm`/`Pair`。
- `hap_sign_tool_lib/hap/config/`：`SignerConfig.java`（证书/算法/signParams/signer/compatibleVersion 载体）。
- `hap_sign_tool_lib/hap/entity/`：HAP 签名块实体（`SigningBlock`/`SignBlockData`/`SignHead`/`SignatureBlockTypes`/`SignatureBlockTags`/`PermissionSignBlock`/`ElfBlockData`/`BlockHead`）。
- `hap_sign_tool_lib/cert/`：`CertBuilder.java`/`CertLevel.java`（按层级构建证书）。

### 按任务类型定位代码

| 任务类型 | 目标位置 | 关键锚点 |
| --- | --- | --- |
| CLI 命令解析/分发 | `hap_sign_tool/.../HapSignTool.java` + `hapsigntoolcmd/CmdUtil.java` | `HapSignTool.java:115`(`main`)、`:137`(`processCmd`)、`:190`(`dispatchParams`)、`:161`(`callGenerators`)；`CmdUtil.java:54`(`convert2Params`)、`:227`(`Method` 常量) |
| 合法参数白名单 | `hapsigntoolcmd/ParamsTrustlist.java` + `resources/help.txt` | `ParamsTrustlist.java:127`(`getTrustList`，由 help.txt 派生，**改 help 即改合法参数集**) |
| 程序化 API（RetMsg） | `hap_sign_tool/.../HapSignTool.java` + `com.ohos.entity/` | `:521`(`signApp`)、`:547`(`verifyApp`)、`:573`(`signProfile`)、`:599`(`verifyProfile`)、`:495`(`reSignEnterpriseApp`) |
| HAP 签名总编排 | `hap_sign_tool_lib/.../hap/provider/SignProvider.java` | `:326`(`sign`)、`:683`(`appendCodeSignBlock`)、`:573`(`appendPermissionSignBlock`)、`:380`(`doSign`)、`:772`(`outputSignedFile`) |
| HAP 签名块构建/摘要 | `hap_sign_tool_lib/.../hap/sign/SignHap.java` | `:225`(`sign`)、`:78`(`generateHapSigningBlock`)、`:190`(`generateSignerBlock`)、`:212`(`Pkcs7Generator.BC.generateSignedData`) |
| PKCS7/CMS 生成+自验 | `hap_sign_tool_lib/.../hap/sign/BcPkcs7Generator.java` | `:85`(`generateSignedData`)、`:107`(`packagePKCS7`)、`:131`(`verifyCmsSignedData` 自验) |
| fs-verity 代码签名（HAP） | `hap_sign_tool_lib/.../codesigning/sign/CodeSigning.java` | `:176`(`getCodeSignBlock`)、`:120`(`getElfCodeSignBlock`)、`:489`(`BcSignedDataGenerator` 带 ownerID) |
| fs-verity 摘要/Merkle 树 | `hap_sign_tool_lib/.../codesigning/fsverity/` | `FsVerityGenerator`、`MerkleTreeBuilder`、`FsVerityDescriptor` |
| profile `.p7b` 生成/自验 | `hap_sign_tool_lib/.../profile/ProfileSignTool.java` | `:89`(`generateP7b`)、`:113`(`signProfile` DER 编码)、`:92`(`verify` 自验) |
| profile 校验/解析 | `hap_sign_tool_lib/.../profile/VerifyHelper.java` + `profile/model/Provision.java` | `VerifyHelper.java:139`(`verify`)、`:194`(`verifyPkcs`)；`Provision.enforceValid` |
| 验签 HAP/ELF | `hap_sign_tool_lib/.../hap/verify/` | `VerifyHap.java:93`(`verify`)；`VerifyElf.java` |
| 密钥库 p12/jks 处理 | `hap_sign_tool_lib/.../utils/KeyStoreHelper.java` | `:107`(ctor)、`:183`(`loadKeyPair`)、`:281`(`store`)、`:338`(`createKeyStoreAccordingFileType`) |
| 远程签名器插件加载 | `hap_sign_tool_lib/.../signer/SignerFactory.java` | `:58`(`getSigner`)、`:72`(`loadRemoteSigner`，URLClassLoader + signer.properties) |
| 证书生成（CSR/CA/端证书） | `hap_sign_tool_lib/.../api/CertTools.java` + `cert/CertBuilder.java` | `SignToolServiceImpl.java:85`(`generateKeyStore`)、`:120`(`generateCert`)、`:146`(`generateCA`)、`:194`(`generateAppCert`) |
| 错误码/异常 | `hap_sign_tool_lib/.../error/` | `ERROR.java`(枚举 0-119)、`CustomException.java:46`(`throwException`)、`SignToolErrMsg.java`(消息常量)、`ErrorMsg.java:35`(子系统 110/111) |
| 日志 | `hap_sign_tool_lib/.../utils/LogUtils.java` + `resources/log.properties` | `LogUtils.java:42`(封装 `java.util.logging`)、`:51`(level 映射)、`:289`(`{}`占位) |
| 参数模型 | `hap_sign_tool_lib/.../entity/Options.java` + `ParamConstants.java` | `Options.java:30`(继承 HashMap)、`ParamConstants.java:23` |
| ZIP 容器操作 | `hap_sign_tool_lib/.../zip/` | `Zip.java`、`CentralDirectory.java`、`Zip64Eocd.java` |
| 构建配置 | `pom.xml`（父） + `hap_sign_tool/pom.xml` + `hap_sign_tool_lib/pom.xml` + `settings.xml` | 父 `pom.xml:13`(Java 8)、`hap_sign_tool/pom.xml:92`(mainClass)、`:88`(shade 输出到 `../hap_sign_tool/build/libs`) |

### 命令行参数（CLI 实况）

> 受信参数由 `resources/help.txt` 经 `ParamsTrustlist.getTrustList`（`ParamsTrustlist.java:127`）派生，**修改 help.txt 即修改合法参数集**。`CmdUtil.convert2Params`（`CmdUtil.java:54`）以 `-key value` 成对解析，键名以 `pwd` 结尾的值转 `char[]` 存储（`CmdUtil.java:109-111`），未知键被受信表拒绝（`CmdUtil.java:77-79`）。

- 命令常量见 `CmdUtil.java:227-282`（`Method` 内部类）与 `help.txt:232-243`：`generate-keypair`/`generate-csr`/`generate-cert`/`generate-ca`/`generate-app-cert`/`generate-profile-cert`/`sign-app`/`verify-app`/`sign-profile`/`verify-profile`/`resign-enterprise-app`。
- `sign-app` 分发到 `runSignApp`（`HapSignTool.java:347`）：`mode` 受限 `localSign`/`remoteSign`（`remoteResign` 未实现，`SignToolServiceImpl.java:313` 返回 false）；`inForm` 受限 `zip`/`elf`/`bin`（`:99-105`），`zip` 为默认；签名算法经 `CmdUtil.judgeEndSignAlgType`（`CmdUtil.java:177-183`）限定 `SHA256withECDSA`/`SHA384withECDSA`；`SignProvider.VALID_SIGN_ALG_NAME`（`SignProvider.java:108-117`）进一步放宽到 `SHA512withECDSA`/RSA/PSS。
- `sign-profile` 分发到 `runSignProfile`（`HapSignTool.java:395`）：`mode` 仅 `localSign`/`remoteSign`；输入签名 profile 为 `.p7b`、未签名为 `.json`；输出 `.p7b`（`:388-392`）。
- `verify-app`/`verify-profile` 分发到 `runVerifyApp`（`:418`）/`runVerifyProfile`（`:431`）。
- `resign-enterprise-app` 分发到 `runReSignEnterpriseApp`（`:442`）：`inForm` 仅允许 `zip`（`:457-460`）。
- 生成类命令（`generate-*`）分发到 `callGenerators`（`:161-188`）。
- 口令交互：`pwdInputMode=1` 时经 `EnterPassword.getPassword`（`EnterPassword.java:42`，`Console` 30s 超时）；否则走命令参数（`HapSignTool.java:80-82`）。
- 远程签名需插件 JAR：`SignerFactory.loadRemoteSigner`（`SignerFactory.java:72`）经 `URLClassLoader` 加载，读 `signer.properties` 中 `ISigner.class.getName()` 键；加载失败回退 stub `RemoteSigner`（抛 `UnsupportedOperationException`）。

## 构建和验证

构建在 `hapsigntool/` 目录执行，使用 Maven3。

1. 确认已安装 Maven3：`mvn -version`（Java 8 编译目标，父 `pom.xml:13-14`）。
2. 在 `developtools_hapsigner/hapsigntool` 执行：

```bash
mvn -s settings.xml clean package
```

3. 编译产物：`hapsigntool/hap_sign_tool/build/libs/hap-sign-tool.jar`（fat jar，shade 插件 `hap_sign_tool/pom.xml:88-89` 指定 `outputDirectory` 为 `../hap_sign_tool/build/libs`、`finalName=hap-sign-tool`、`mainClass=com.ohos.hapsigntool.HapSignTool`）。
4. 依赖经华为云 Maven 镜像（`settings.xml`：`https://mirrors.huaweicloud.com/repository/maven/`）；父 `pom.xml` 的 `dependencyManagement` 锁定 `gson` 2.11.0、`bcpkix-jdk18on` 1.82、`log4j-core/api` 2.25.4、`junit-jupiter` 5.11.0。

测试使用 JUnit 5（Jupiter 5.11.0，父 `pom.xml:18`）。关键测试套件：

- `hap_sign_tool/src/test/java/com/ohos/hapsigntoolcmd/CmdUnitTest.java`（1226 行）：端到端集成测试，按 `@TestMethodOrder` 顺序执行完整链路（`generate-keypair`→`generate-ca`→`generate-cert`→`generate-app-cert`→`generate-profile-cert`→`sign-profile`→`verify-profile`→`sign-app`→`verify-app`），引用 `../../tools/` 下 fixtures（`app1.pem`/`app1-profile.p7b`/`ohtest_pass.jks` 等），需从 `hap_sign_tool/` 目录执行。
- `hap_sign_tool/src/test/java/com/ohos/hapsigntoolcmd/HapSignToolTest.java`（277 行）：程序化 API 测试（`signApp`/`verifyApp` + `Mode.LOCAL_SIGN` + `InForm.ELF`），含 `testSignElf`、负参测试。
- `hap_sign_tool/src/test/java/com/ohos/hapsigntoolcmd/ConcurrencyTest.java`（269 行）：`@RepeatedTest` 并发签名压力测试。
- `hap_sign_tool_lib/src/test/java/com/ohos/hapsigntool/`：单元测试（`ProfileTest`/`HapUtilsTest`/`KeyStoreTest`/`KeyPairTest`/`CertTest`/`LogUtilsTest`/`profile/model/ProvisionTest`/`hap/verify/X509CertificateSelectorTest`）。

测试资源：`hap_sign_tool_lib/src/test/resources/`（`UnsgnedDebugProfileTemplate.json`/`test-profile-cert.cer`/`log.properties`）、`hap_sign_tool/src/test/resources/`（`UnsgnedReleaseProfileTemplate.json`/`UnsgnedDebugProfileTemplate.json`/`entry-default-unsigned.hap`）。执行：

```bash
mvn -s settings.xml test
```

> 注意：`CmdUnitTest` 引用模块外的 `../../tools/` fixtures，执行前需确认该目录存在；测试从 `hap_sign_tool/` 工作目录运行。

静态检查：`-Xlint:all` 已编入父 `pom.xml` 编译参数，`mvn -s settings.xml -DskipTests=true clean package` 可观察全部编译告警；改动不得引入新增告警或抬升告警级别。子模块可加 `maven-checkstyle-plugin`/spotbugs（若已配置）按 `mvn -s settings.xml checkstyle:check`/`spotbugs:check` 单独跑。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已完成** - `git commit -s`
2. **本地构建通过** - `mvn -s settings.xml clean package` 成功，产物 `hap-sign-tool.jar` 生成
3. **相关测试通过** - 受影响的 JUnit5 目标执行并提供输出摘要（`mvn -s settings.xml test`）
4. **签名格式双向核对** - 触及签名块结构/magic/常量/fs-verity 时，确认与 C++ 版 `hapsigntool_cpp/`、`binary_sign_tool/` 字节兼容（三实现共享格式规范，见"项目约束"）
5. **安全清单逐条核对** - 见"项目约束→安全关键约束"

### 如果无法运行验证

说明原因（如需真实 keystore/`.p12` 证书链、远程签名器插件 JAR、`../../tools/` 测试 fixtures、或真机验签环境），列出推荐验证步骤与预期输出关键字供人工执行，不得声称已验证。

### 完成报告格式

改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（签名格式兼容性、密钥与密码安全、HAP 块布局、跨版本）、未完成事项。

## 知识索引

本目录暂无独立 `docs/knowledge/`，稳定背景知识以代码与常量定义为准，改动前按场景读取：

| 场景 | 修改位置 | 先读锚点 |
| --- | --- | --- |
| 命令/help 文本/受信参数 | `hap_sign_tool/.../hapsigntoolcmd/` + `resources/help.txt` | `CmdUtil.java:54`(`convert2Params`)、`:227`(`Method` 常量)；`ParamsTrustlist.java:127`(`getTrustList`，参数白名单由 help.txt 派生，**改 help 即改合法参数集**) |
| 签名总流程 | `api/SignToolServiceImpl.java` + `hap/provider/SignProvider.java` | `SignToolServiceImpl.java:304`(`signHap`)、`:320`/`:322`/`:324`(inForm 分发)；`SignProvider.java:326`(`sign` 编排) |
| HAP 签名块格式 | `hap/sign/SignHap.java` + `hap/utils/HapUtils.java` | `SignHap.java:100-163`(块布局注释)；`HapUtils.java:75-110`(block ID)、`:156-171`(magic V2/V3)、`:196`(MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3=8) |
| PKCS7/CMS | `hap/sign/BcPkcs7Generator.java` | `:85`(`generateSignedData`)、`:127`(DER/BER 编码)、`:131`(自验签) |
| fs-verity 描述符/digest/Merkle | `codesigning/fsverity/` | `FsVerityGenerator`、`MerkleTreeBuilder`、`FsVerityDescriptor`；4K 对齐见 `codesigning/utils/HapUtils` 与 `CodeSignBlock.PAGE_SIZE_4K` |
| 代码签名块组装（HAP/ELF） | `codesigning/sign/CodeSigning.java` | `:176`(`getCodeSignBlock`)、`:120`(`getElfCodeSignBlock`)、`:350`(`isElfFile`) |
| profile 校验/解析 | `profile/ProfileSignTool.java` + `profile/VerifyHelper.java` + `profile/model/Provision.java` | `ProfileSignTool.java:89`(`generateP7b`)、`:113`(`signProfile`)；`VerifyHelper.java:139` |
| 远程签名器插件 | `signer/SignerFactory.java` + `signer/ISigner.java` | `SignerFactory.java:72`(`loadRemoteSigner`，URLClassLoader + `signer.properties`)；`RemoteSigner.java:52`(stub 抛异常) |
| 密钥库/口令 | `utils/KeyStoreHelper.java` + `utils/EnterPassword.java` | `KeyStoreHelper.java:107`/`:183`/`:281`/`:338`(p12/jks)；`EnterPassword.java:42`(Console 30s) |
| 错误码 | `error/ERROR.java` + `error/SignToolErrMsg.java` + `error/ErrorMsg.java` | `ERROR.java`(0-119)；`ErrorMsg.java:35`(子系统 110 sign-tool / 111 code-sign) |
| 日志 | `utils/LogUtils.java` + `resources/log.properties` | `LogUtils.java:42`(`java.util.logging`)、`:51-55`(level 映射)、`:289`(`{}`占位) |
| 参数模型 | `entity/Options.java` + `entity/ParamConstants.java` | `Options.java:30`(HashMap)；`ParamConstants.java:27`(legacy 20001-20004) |
| 构建配置 | `pom.xml` + `hap_sign_tool/pom.xml` + `hap_sign_tool_lib/pom.xml` | 父 `pom.xml:13`(Java 8)、`:26`(dependencyManagement)；`hap_sign_tool/pom.xml:92`(mainClass)、`:88`(shade 输出) |

### 词汇路由

任务/日志/issue/API 中若出现下列域词，先命中"知识索引"对应行再编辑：

| 域词 | 命中"知识索引"行 |
| --- | --- |
| `HAP Sig Block 42` / `<hap sign block>` / magic V2/V3 / block ID | HAP 签名块格式 |
| `fs-verity` / Merkle 树 / `FS_SHA256`/`FS_SHA512` / 4K 对齐 / `CodeSignBlock` | fs-verity 描述符/digest/Merkle、代码签名块组装 |
| `ownerID OID`（`1.3.6.1.4.1.2011.2.376.1.4.1`）/ `BcSignedDataGenerator` | PKCS7/CMS（触发与 C++/binary_sign_tool 三向核对） |
| `Provision` / `.p7b` / `ProfileSignTool` | profile 校验/解析 |
| `RetMsg` / `signApp`/`verifyApp`/`signProfile`/`verifyProfile`/`reSignEnterpriseApp` | 程序化 API（RetMsg），见"项目约束→Ask before" |
| `signer.properties` / `RemoteSigner` / `URLClassLoader` / `ISigner` | 远程签名器插件 |
| `help.txt` / `ParamsTrustlist` / 受信参数 | 命令/help 文本/受信参数（**改 help 即改合法参数集**） |
| `EnterPassword` / `pwdInputMode` / `char[]` 口令 | 密钥库/口令（见安全关键约束） |
| `FileUtils` / `validFileType` / `isValidFile` | 路径校验（见安全关键约束） |

### 开始编辑前

1. 确认任务类别，按上表定位锚点
2. 涉及签名格式/magic/block ID/fs-verity 常量时，先确认与 `hapsigntool_cpp/`、`binary_sign_tool/` 字节兼容
3. 根据"项目约束"确认不违反任何约束
4. 声明："修改目标：X；已读锚点：Y；遵循约束：Z"

## 编码约定

- **4 空格**缩进禁 Tab；**Java 8**（`maven.compiler.source/target=8`，父 `pom.xml:13-14`，`-Xlint:all`），不得使用 Java 9+ 特性（`var`/records/`module-info`/`List.of`/`Map.of`）；shade 插件显式排除 `module-info.class`（`hap_sign_tool/pom.xml:100-117`）。
- 包名全小写层级（`com.ohos.hapsigntool`（库）/`com.ohos.hapsigntoolcmd`（CLI cmd 层）/`com.ohos.entity`（程序化 API POJO））；类名 PascalCase（`HapSignTool`/`SignToolServiceImpl`/`BcPkcs7Generator`），缩写有时保留大写（`HAP`/`JKS`/`CMS`/`PKCS7`），有时标题化（`Hap`/`Csr`）；方法 camelCase（`signHap`/`generateP7b`/`convert2Params`）；异常类后缀 `Exception`。
- 大括号 K&R 风格（同行开括号）；每个源文件以 Apache 2.0 版权头起始（`Copyright (c) Huawei Device Co., Ltd.`）；公开方法/常量写 Javadoc（`@param`/`@return`/`@throws`/`@since`）。
- 密码学：`Security.addProvider(new BouncyCastleProvider())` 静态注册（`SignToolServiceImpl.java:75`/`SignProvider.java:118`/`VerifyHap.java:101`）；签名能力 OID 嵌入证书扩展（app `{0x30,0x06,0x02,0x01,0x01,0x0A,0x01,0x00}`、profile `{...,0x0A,0x01,0x01}`，`SignToolServiceImpl.java:62-67`）。
- 内存/口令：口令存 `char[]` 不存 `String`（`CmdUtil.java:109-111` 转 `toCharArray`；`Options.getChars`）；用毕 `adapter.releasePwd()` 清零（`SignToolServiceImpl` 多处）；`KeyStoreHelper` 口令 `char[]`（`:94`）。
- 日志：`private static final LogUtils LOGGER = new LogUtils(<Class>.class)`，`LOGGER.info/debug/warn/error(...)`，支持 `{}` 占位（`LogUtils.java:289-311`）；`info`→`Level.INFO`、`debug`→`Level.CONFIG`、`warn`→`Level.WARNING`、`error`→`Level.SEVERE`（`:51-55`）。`OUT_HANDLER`（stdout 非严重）+ `ERR_HANDLER`（stderr 警告+，`:65-69`）。注：`ErrorMsg.java` 另用 `org.apache.logging.log4j.LogManager`，但应用日志统一走 `LogUtils`。
- 异常：域异常继承 `RuntimeException`（`CustomException`）或为受检异常（`ProfileException`/`SignatureException`）；抛出经 `CustomException.throwException(ERROR.<code>, SignToolErrMsg.<MSG>.toString(...))` 工厂；入口与 `RetMsg` API 方法捕获宽 `Exception` 转返回码（`HapSignTool.java:121-127`/`:510-537`）。
- 常量 `public static final`；魔法数在注释中记录二进制布局；无 Lombok，手写 getter/setter/构造。
- 测试：JUnit 5（`@Test`/`@BeforeAll`/`@RepeatedTest`/`@TestMethodOrder`/`@Order`），资源放 `src/test/resources/`，fixtures 引用 `../../tools/`（需从 `hap_sign_tool/` 运行）。

## 项目约束

### 安全关键约束（红线，改动必查）

**Do not（禁止）：**
- 在日志/`LOGGER` 输出明文口令、私钥、keystore 内容：口令以 `char[]` 形式存于 `Options`（`CmdUtil.java:109-111`），键名以 `pwd` 结尾；`EnterPassword.getPassword`（`EnterPassword.java:42`）经 `Console` 无回显 + 30s 超时；`adapter.releasePwd()` 用毕清零。`LocalJKSSignProvider.checkParams`（`LocalJKSSignProvider.java:101-102`）将 `char[]` 转 `String` 供 signParams 是已知弱化，不得进一步扩散。
- 绕过 `FileUtils.validFileType`/`isValidFile`/`checkFile` 直接信任用户传入路径：必须校验后缀（`p7b`/`p12`/`jks`/`cer`/`json`/`csr`，`HapSignTool.java:230`/`:389`/`:413`/`:426-427`/`:433`）、可读性（`SignProvider.java:182-193`）；输入==输出同路径时先写临时文件再原子移动（`SignProvider.java:337-338`/`:789-796`），失败清理（`:801`）。
- 破坏 HAP 签名块字节格式：magic 字 `HAP_SIGNING_BLOCK_MAGIC_V2`（`"HAP Sig Block 42"`，`HapUtils.java:216-217`）/`MAGIC_V3`（`"<hap sign block>"`，`:222-223`）与对应 long（`:156-171`）、block ID（`:75-110`，如 `HAP_SIGNATURE_SCHEME_V1_BLOCK_ID=0x20000000`/`HAP_CODE_SIGN_BLOCK_ID=0x30000001`/`PERMISSION_SIGN_BLOCK_ID=0x30000002`）、版本号（V2=2/V3=3，`:146`/`:151`）、`MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3=8`（`:196`）均为设备端验签强依赖，多字节整数统一**小端**（`ByteOrder.LITTLE_ENDIAN`，`SignHap.java:141`/`SignProvider.java:633/698/723`）。
- 破坏 4K 对齐：`CodeSignBlock.PAGE_SIZE_4K=4096`，`computeDataSize` 强制 `dataSize % 4096 == 0`（`CodeSigning.java:232-258`）；fs-verity 描述符/Merkle 树常量须与内核 fs-verity 规范一致。
- 超过签名文件大小上限：`Zip.MAX_APP_FILE_LENGTH`（200GB，`SignProvider.java:777-779`）；Zip64 仅 `.app` 后缀允许（`SignProvider.java:106`/`:856-861`）。
- 随意接受任意签名算法：端证书/profile/app 签名算法限 `SHA256withECDSA`/`SHA384withECDSA`（`CmdUtil.java:177-183`）；通用算法限 `SHA256/384withRSA`+ECDSA 两族（`:163-170`）；密钥算法限 `RSA`/`ECC`（`:124-129`）；密钥长度 `RSA{2048,3072,4096}`/`ECC{NIST-P-256,NIST-P-384}`（`:137-156`）；HAP 签名另接受 `SHA512withECDSA`/RSA/PSS/MGF1（`SignProvider.java:108-117`）。新增算法须同时改 `CmdUtil` 判定与 `SignProvider.VALID_SIGN_ALG_NAME`。
- 信任不受控的远程签名器插件：`SignerFactory.loadRemoteSigner`（`SignerFactory.java:72`）经 `URLClassLoader` 加载任意 JAR，先相对 CWD 再相对运行 jar 目录查找（`:79-87`/`:133-153`）；插件须实现 `ISigner` 并在 `signer.properties` 注册；加载失败回退 stub（抛 `UnsupportedOperationException`）。`RemoteSigner` 本身为 stub（`RemoteSigner.java:52`）。

**Ask before（修改前必须确认）：**
- 修改 `ServiceApi` 接口方法签名（`ServiceApi.java:25`）或 `HapSignTool` 程序化静态方法（`signApp`/`verifyApp`/`signProfile`/`verifyProfile`/`reSignEnterpriseApp`）或 `com.ohos.entity.*Parameters` POJO 字段或 `RetMsg`/`ERROR` 枚举序号：构成对外稳定 API，破坏将影响下游消费方。
- 修改 HAP 签名块 magic/block ID/版本/`MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3`/`PERMISSION_SIGN_MAGIC`（`HapUtils.java`）：设备端验签与跨版本兼容性强相关。
- 修改 fs-verity 常量（页大小 4K、`FsVerityDescriptor` 版本/字段、`FsVerityHashAlgorithm` id）：内核 fs-verity 校验依赖。
- 修改 `help.txt`：合法参数白名单由其派生（`ParamsTrustlist.java:127`），删/改参数名直接影响命令行接受能力。
- 修改 `signer.properties` 键名或 `ISigner` 接口：远程签名器插件兼容性。
- 修改签名能力 OID 字节数组（`SignToolServiceImpl.java:62-67`）：影响证书签发能力识别与验签匹配。
- 修改 `ErrorMsg` 子系统码（`110`/`111`）或 `ERROR` 枚举码值（0-119）/`ParamConstants` legacy 码（`20001-20004`）：错误码契约稳定性。
- 升级第三方依赖（`bcpkix-jdk18on`/`gson`/`log4j`/`junit-jupiter` 等）版本：须核对 license 兼容性与签名字节兼容性，不得静默升版；版本由父 `pom.xml:26` 的 `dependencyManagement` 锁定。

### 架构约束

- **双模块模型**：`hap_sign_tool_lib/`（核心库，无 main）+ `hap_sign_tool/`（CLI 应用，依赖 lib，shade 打 fat jar）。核心签名逻辑全部在 lib；CLI 仅做命令解析/分发/参数校验与程序化 API POJO。改动签名核心应落 lib，改动 CLI 行为落 `hap_sign_tool/.../hapsigntoolcmd/`。
- **Provider 分轨**：`SignToolServiceImpl.signHap`（`:304`）按 `mode`(`localSign`/`remoteSign`)选 `LocalJKSSignProvider`/`RemoteSignProvider`，按 `inForm`(`zip`/`elf`/`bin`)分发 `sign`/`signElf`/`signBin`（`:320`/`:322`/`:324`）。`remoteResign` 模式未实现（`SignToolServiceImpl.java:313` 返回 false）。新增模式应扩展 `CmdUtil.Method`、`help.txt`、`SignToolServiceImpl` 与 provider，勿在现有分支硬编码。
- **签名总流程不可乱序**：`SignProvider.sign`（`:326`）必须 拷贝并对齐 ZIP → 经自定义 `Zip` 操作 → 追加 code-sign 块（`appendCodeSignBlock` `:683`）→ 追加权限块（`appendPermissionSignBlock` `:573`）→ `doSign`（`:380`）经 `SignHap.sign` 计算摘要并生成签名 → `outputSignedFile`（`:772`）。摘要计算依赖块布局最终状态，乱序将导致摘要失真。
- **PKCS7/Profile 自验签**：`BcPkcs7Generator.generateSignedData`（`:85`）在打包后调用 `VerifyUtils.verifyCmsSignedData`（`:131-140`）自验；`ProfileSignTool.generateP7b`（`:89`）在返回前自验（`:92-102`）——产出无效签名的防线，不得移除。
- **自定义 ZIP 不引入第三方 zip 库**：签名直接操作 ZIP 容器（`zip/` 包全自实现 EOCD/Zip64/CentralDirectory），引入新依赖会破坏 fat jar 装配（shade 排除列表 `hap_sign_tool/pom.xml:103-115` 暗示历史 META-INF 冲突）。
- **验签只读不写**：`VerifyHap`/`VerifyElf`/`VerifyHelper` 仅解析与验证，不得修改输入文件。
- **三实现格式同步**：本工具（Java）与 `hapsigntool_cpp/`（C++）、`binary_sign_tool/`（C++ ELF）共享签名格式规范（HAP 块 magic/ID、fs-verity 常量、PKCS7/CMS、ownerID OID `1.3.6.1.4.1.2011.2.376.1.4.1`），但无代码依赖；改格式须三处同步并保证字节兼容。
- **程序化静态 API 的并发安全**：`HapSignTool` 静态方法（`signApp`/`verifyApp`/`signProfile`/`verifyProfile`/`reSignEnterpriseApp`，`HapSignTool.java:521`/`:547`/`:573`/`:599`/`:495`）设计为可多线程并发调用——`ConcurrencyTest`（`hap_sign_tool/src/test/java/com/ohos/hapsigntoolcmd/ConcurrencyTest.java`）以 100 并发任务循环压测全链路即为此契约的验证。每次调用须保持无状态：不得把本次调用的中间态/口令/密钥泄漏进静态字段；确需跨调用复用的静态可变状态（如 `SignerFactory.SIGNER_LOADERS` ClassLoader 缓存 `:50`）必须显式同步（`generateSignerClassLoader` 为 `synchronized` `:155`）。改动不得引入未同步的静态可变字段（缓存/计数器/单例可变状态）而破坏已有并发契约；涉及并发语义变更须跑 `ConcurrencyTest` 复验。
