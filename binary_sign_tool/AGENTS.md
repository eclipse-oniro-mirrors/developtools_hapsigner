# binary_sign_tool 组件指引（OpenHarmony hapsigner / binary-sign-tool）

> 本仓库面向 Agent 的指导文档统一使用中文；代码标识符、命令、路径、文件名保留原文。本工具为 C++17 主机侧 ELF 二进制签名工具（可执行目标 `binary-sign-tool`），对二进制 ELF 文件（可执行 bin 或 so）签名，签名后方可在真机设备运行/调试；在支持强制代码签名的设备上为二进制文件提供运行时合法性校验与完整性保护。属 `developtools` 子系统下 `hapsigner` 部件，基于 openharmony 标准系统 **ohos-sdk 形态**编译构建，使用前需先配置 openharmony 开发环境并使用 C++17 及以上语言标准。核心逻辑直接调用 OpenSSL（PKCS7/X509/EVP/HMAC），无 HUKS/AlgLoader 抽象层；禁 RTTI（`-fno-rtti`），不使用异常。工具仅支持 **ECC** 密钥算法；README 声明仅支持 PKCS#12（`.p12`）密钥库，但代码 `params_run_tool.cpp:135` 的后缀校验实际接受 `p12`/`jks`；支持交互式输入 `keyPwd`/`keystorePwd`，口令校验失败时请求手动输入，超时 30 秒。

## 项目定位

本目录是 hapsigner 的**原生 ELF 二进制签名入口**，与 Java 版 `hapsigntool/`、C++ 版 HAP 库 `hapsigntool_cpp/` 并列。大量源码以 `.gni` 聚合方式复用 `hapsigntool_cpp/`（signer / common / utils / cmd / profile / codesigning / hap 的部分实现），二进制签名专有逻辑在 `binary_sign_tool/` 本目录下。

优先按这些目录定位问题：

- `main.cpp`：进程入口，加载 OpenSSL default/legacy provider 后转交 `ParamsRunTool::ProcessCmd`。
- `cmd/`：命令行解析与分发。`params_run_tool.cpp` 按 method 分发 `sign`/`display-sign`；`params_trust_list.cpp` 由 `help.h` 的 `HELP_TXT` 自动生成参数白名单；`cmd_util.cpp` 做参数校验、`realpath` 归一化与类型转换。
- `api/`：服务门面。`service_api.h` 抽象基类 `ServiceApi`（`Sign`/`Verify`），`sign_tool_service_impl.cpp` 按 `selfSign`/`localSign`/`remoteSign` 选择 `SignProvider`，验签委派 `VerifyElf`。
- `hap/`：ELF 签名/验签主体。`provider/`（`SignProvider` 基类 + `LocalSignProvider`/`RemoteSignProvider`/`SelfSignSignProvider`）、`sign/`（`SignElf` 写段、`BCPkcs7Generator` 打包 PKCS7）、`verify/`（`VerifyElf` 解析 `.codesign`）、`entity/`（`ParamConstants`、签名算法/摘要算法 helper、`block_head`）、`utils/`（`dynamic_lib_handle` 远程签名器 so 句柄）。
- `codesigning/`：fs-verity 生成。`fsverity/`（`FsVerityGenerator`、`MerkleTreeBuilder`、`FsVerityDescriptor`）、`sign/code_signing.cpp` 组装 `ElfSignInfo`（描述符 + 签名）。
- `profile/`：`profile_sign_tool.cpp`（profile p7b 生成/自验）、`profile_info.cpp`（provision 解析）。
- `common/`：`options.h`（`Options` 即 `unordered_map<string, variant<string,int,bool,char*>>`）、`constant.h`（命令名/算法名/段名常量）、`signature_tools_log.h`（printf 式日志 + `PrintErrorNumberMsg`/`PrintMsg`）、`password_guard.h`（无回显终端密码采集 + memset_s 清零）。
- `utils/`：`file_utils`（文件读写/校验/拷贝权限）、`compare_elf`（签名前后 ELF 段/段表一致性校验）。
- `signer/`：仅 `binary_sign_tool_signer.gni`，源码全部来自 `hapsigntool_cpp/signer/`（`LocalSigner`、`SignerFactory`）。
- `hapsigntool_cpp/`：被复用的共享库，详见其目录；本工具经各 `signature_tools_*.gni` 把它的 `signer/common/utils/cmd/codesigning/profile/hap` 部分源文件编进 `binary-sign-tool`。
- `hapsigntool_cpp_test/`：gtest 单测，含 `hapSign/sign_elf_test`、`codeSigning/code_signing_test`、`elfVerify/verify_elf_test`、`signProfile/`、`fuzztest/`。

### 按任务类型定位代码

| 任务类型 | 首选位置 | 关键锚点 |
| --- | --- | --- |
| 新增/修改命令或参数 | `cmd/include/help.h` + `cmd/src/params_run_tool.cpp` + `cmd/src/cmd_util.cpp` + `params_trust_list.cpp` | `params_run_tool.cpp:30`(`DISPATCH_RUN_METHOD`)、`:109`(`RunSignApp`)、`help.h:30`(`SIGN_HELP_TXT`) |
| 签名模式分支（self/local/remote） | `api/src/sign_tool_service_impl.cpp` + `hap/provider/` | `sign_tool_service_impl.cpp:39`(provider 选择) |
| ELF 写段流程（.codesign/.profile/.permission） | `hap/sign/src/sign_elf.cpp` | `sign_elf.cpp:32`(`SignElf::Sign`)、`:137`(`WriteCodeSignBlock`)、`:183`(`WriteSecDataToFile`) |
| fs-verity Merkle 树/digest/descriptor | `codesigning/fsverity/` | `fs_verity_generator.cpp:33`(`GenerateFsVerityDigest`)、`merkle_tree_builder.h:33` |
| 组装 ElfSignInfo（描述符+签名） | `codesigning/sign/src/code_signing.cpp` | `code_signing.cpp:41`(`GetElfCodeSignBlock`)、`:91`(`GenerateSignature`) |
| PKCS7 signedData 打包 | `hap/sign/src/bc_pkcs7_generator.cpp`（复用 `hapsigntool_cpp` 的 `bc_signeddata_generator`/`pkcs7_data`） | `bc_pkcs7_generator.cpp:30`(`GenerateSignedData`) |
| profile p7b 生成/自验 | `profile/src/profile_sign_tool.cpp` | `profile_sign_tool.cpp:47`(`SignProfile`) |
| ELF 验签/展示签名信息 | `hap/verify/src/verify_elf.cpp` | `verify_elf.cpp:28`(`Verify`)、`:78`(`ParseSignBlock`) |
| 密钥库/证书读取、私钥采集 | `utils/`（复用 `hapsigntool_cpp/utils/key_store_helper`）+ `cmd/src/params_run_tool.cpp:69`(`UpdateParamForPwd`) | `password_guard.h:95`(`getPasswordFromUser`) |
| 远程签名器 so 插件加载 | `hapsigntool_cpp/signer/src/signer_factory.cpp` + `hap/utils/include/dynamic_lib_handle.h` | `signer_factory.cpp:42`(`LoadRemoteSigner`) |
| 签名前后 ELF 一致性校验 | `utils/src/compare_elf.cpp` | `compare_elf.h:27`(`CompareElf`) |
| 错误码/日志 | `hapsigntool_cpp/common/include/signature_tools_errno.h` + `common/include/signature_tools_log.h` | `signature_tools_errno.h:21`(`RET_OK`…) |
| 构建目标/源码裁剪 | `BUILD.gn` + 各 `signature_tools_*.gni` + `signature_tools.gni` | `BUILD.gn:53`(`ohos_executable`)、`signature_tools.gni:14` |

### 命令行参数（CLI 实况）

> 以下以代码为准；README “接口说明/使用说明” 与实际 CLI 有出入（见各条标注）。

- `sign` 的受信参数由 `help.h` 的 `SIGN_HELP_TXT` 经 `ParamsTrustList::ReadHelpParam`（`params_trust_list.cpp:55`）派生，共 12 个：`-keyAlias`/`-keyPwd`/`-appCertFile`/`-profileFile`/`-profileSigned`/`-inFile`/`-signAlg`/`-keystoreFile`/`-keystorePwd`/`-outFile`/`-moduleFile`/`-selfSign`。不在该集合的参数（如 `-mode`/`-signCode`/`-signerPlugin`）会被 `cmd_util.cpp:294`(`GetCommandParameterKey`) 以 “not trust command” 拒绝。
- README “接口说明” 列出 `-mode`（localSign/remoteSign，默认 localSign），但当前 `binary_sign_tool` **未把 `-mode` 纳入 `help.h`/受信表**，`cmd_util.cpp:342` 直接 `emplace(Options::MODE, LOCAL_SIGN)`，故 `RemoteSignProvider`（`sign_tool_service_impl.cpp:43`）与 `-signerPlugin` 代码路径在 CLI 下**不可达**，实际可用模式为 **selfSign** 与 **localSign**。若需启用 remoteSign，须同时改 `help.h`、`ParamsTrustList` 与 `cmd_util` 的 MODE 处理。
- 自签名：`binary-sign-tool sign -inFile <in> -outFile <out> -selfSign 1`，仅需 `inFile`/`outFile`/`selfSign`——`RunSignApp`（`params_run_tool.cpp:128`）在 localSign 必填校验（`keystoreFile`/`keyAlias`/`appCertFile`）之前提前 `return api.Sign`。
- 证书签名：`binary-sign-tool sign -keyAlias ... -signAlg SHA256withECDSA -appCertFile <pem> -profileFile <p7b> -profileSigned 1 -inFile <elf> -keystoreFile <p12> -outFile <out> -keyPwd ... -keystorePwd ... -moduleFile <module.json>`（与 README 示例一致）。
- `display-sign`：仅需 `-inFile`，输出 `.permission`(JSON) 与 `.codesign` 内证书链信息。
- SDK 签名相关文件（`dist/`）：`OpenHarmony.p12`（密钥库）、`OpenHarmonyApplication.pem`（应用签名证书）、`binary-sign-tool`/`binary-sign-tool.jar`（工具）。


## 构建和验证

构建在 OpenHarmony 源码根目录执行，不在本子目录执行。本工具分 Java 版与 C++ 版两条编译流程。

**C++ 版编译流程（`binary_sign_tool/`）**

1. 编译 ohos-sdk 形态签名工具：
   + **release** 版本：默认即 release，直接编译。
   + **debug** 版本（增加调试日志）：在 `binary_sign_tool/BUILD.gn` 中添加 `defines = [ "SIGNATURE_LOG_DEBUG" ]` 即可（该宏控制 `SIGNATURE_TOOLS_LOGI/LOGD` 是否编译，见 `common/include/signature_tools_log.h:38`）。
2. 编译命令：

```bash
./build.sh --product-name ohos-sdk
```

3. 编译产物路径：`/openharmony_master/out/sdk/packages/ohos-sdk`（可执行 `binary-sign-tool`）。`BUILD.gn:24` 的 `ohos_copy("copy_signature_tools_resource")` 另把 `../dist/`（`OpenHarmony.p12`、`OpenHarmonyApplication.pem`、`OpenHarmonyProfileDebug.pem`、`OpenHarmonyProfileRelease.pem`、`*.p7b`/`*.json` 模板）拷到 `toolchains/hapsigntool_pc/`。

**Java 版编译流程（`binary_sign_tool/java/`）**

1. 确认已安装 Maven3：`mvn -version`。
2. 进入 `developtools_hapsigner/binary_sign_tool/java` 执行：

```bash
mvn package
```

3. 编译产物目录：`./build/libs`（`binary-sign-tool.jar` 等）。

**编译装配与依赖**（`binary_sign_tool/BUILD.gn`）：`ohos_executable("binary-sign-tool")` 经各 `signature_tools_*.gni` 聚合源码——本目录覆盖版（`sign_elf.cpp`/`bc_pkcs7_generator.cpp`/`fs_verity_generator.cpp`/`merkle_tree_builder.cpp`/`code_signing.cpp`/`profile_sign_tool.cpp`/`options.cpp`/`file_utils.cpp`/`compare_elf.cpp` 等）+ 复用 `hapsigntool_cpp/` 的 signer/common/utils/cmd/profile/codesigning/hap 部分。外部依赖（`BUILD.gn:78`）：`bounds_checking_function:libsec_static`（`memset_s/memcpy_s`）、`elfio:elfio`（ELF 读写）、`cJSON:cjson_static`、`openssl:libcrypto_static`+`openssl:libssl_static`。编译选项 `-std=c++17 -fno-rtti`；移除 `//build/config:executable_config`；`install_enable = false`、`install_images = ["system"]`、`part_name = "hapsigner"`、`subsystem_name = "developtools"`。

测试位于 `hapsigntool_cpp_test/`（gtest，源集 `hapsigntool_cpp_test/BUILD.gn` 引用 `hapsigntool_cpp/` 的 `.gni`，`--coverage` 编译，链接 openssl shared + `cJSON`/`zlib`/`hilog`/`c_utils`）。与 ELF 签名相关的套件：`unittest/hapSign/sign_elf_test`、`unittest/hapSign/sign_provider_test`、`unittest/codeSigning/code_signing_test`、`unittest/codeSigning/fsverity/*`、`unittest/elfVerify/verify_elf_test`、`unittest/elfVerify/signing_block_test`、`unittest/signProfile/sign_profile_test`；另有 `fuzztest/`。编译后过滤执行：

```bash
out/<product>/.../sign_elf_test --gtest_filter=SignElfTest.*
out/<product>/.../verify_elf_test --gtest_filter=VerifyElfTest.*
```

> 注意：单测工程引用 `hapsigntool_cpp/` 的 `.gni`，与本工具 `binary_sign_tool/` 版 `.gni` 源文件清单**略有差异**（本工具额外含 `sign_elf.cpp`/`bc_pkcs7_generator.cpp` 的本目录实现、`compare_elf.cpp`），同步两套实现时需双向核对。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已完成** - `git commit -s`
2. **本地构建通过** - `./build.sh --product-name ohos-sdk` 编译成功，产物位于 `/openharmony_master/out/sdk/packages/ohos-sdk`
3. **相关测试通过** - 受影响的 gtest 目标执行并提供输出摘要
4. **共享代码双向核对** - 同时触及 `binary_sign_tool/` 与 `hapsigntool_cpp/` 同名实现时，确认两处语义一致（本工具的部分源文件以覆盖/重写形式参与编译，见各 `.gni`）
5. **安全清单逐条核对** - 见“项目约束→安全关键约束”

### 如果无法运行验证

说明原因（如需真实 keystore/.p12 证书链、或远程签名器 so 插件、或板侧 fs-verity 内核能力），列出推荐验证步骤与预期输出关键字（如 `add codesign section success`、`write code sign data success`、`code signature is self-sign`）供人工执行，不得声称已验证。

### 完成报告格式

改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（ELF 段布局/签名格式兼容性、密钥与密码安全、跨版本）、未完成事项。

## 知识索引

本目录暂无独立 `docs/knowledge/`，稳定背景知识以代码与常量定义为准，改动前按场景读取：

| 场景 | 修改位置 | 先读锚点 |
| --- | --- | --- |
| 命令/参数/help 文本 | `cmd/` | `help.h:30`(`SIGN_HELP_TXT`/`VERIFY_HELP_TXT`)、`params_trust_list.cpp:55`(`ReadHelpParam`，参数白名单由 help 文本派生，**改 help 即改合法参数集**) |
| 签名总流程 | `api/` + `hap/provider/` + `hap/sign/` | `sign_tool_service_impl.cpp:29`、`sign_provider.cpp:47`(`SignElf` 编排)、`sign_elf.cpp:32` |
| .codesign 段 4K 占位+回填 | `hap/sign/src/sign_elf.cpp` | `:137`(`WriteCodeSignBlock`)、`:220`(`GenerateCodeSignByte`)、`:250`(`ReplaceDataOffset`) |
| fs-verity 描述符/digest/merkle 树 | `codesigning/fsverity/` | `fs_verity_generator.cpp:33`、`merkle_tree_builder.h:33`；常量 `LOG_2_OF_FSVERITY_HASH_PAGE_SIZE=12`(4096页)、`ELF_CODE_SIGN_VERSION=0x3`、`FS_SHA256` |
| ElfSignInfo 布局 | `hap/verify/include/verify_elf.h` | `:30`(`ElfSignInfo` 结构体，含 `rootHash[64]`/`salt[32]`/`flags`/`csVersion`/`signature[0]`) |
| PKCS7/BCSignedData | `hap/sign/src/bc_pkcs7_generator.cpp` + `hapsigntool_cpp/codesigning/sign/src/bc_signeddata_generator.cpp` | `bc_pkcs7_generator.cpp:30`；ownerID OID 见 `constant.h:55`(`OWNERID_OID`) |
| profile 校验/解析 | `profile/` + `hapsigntool_cpp/profile/`(`profile_verify`/`pkcs7_data`) | `sign_provider.cpp:293`(`CheckProfileValid`)、`profile_sign_tool.cpp:47` |
| 远程签名器插件 ABI | `hapsigntool_cpp/signer/include/signer_factory.h` | `:32`(`RemoteSignerCreator` 签名：5 个 `RemoteSignerParamType`)、`:65`(`dlsym "GetRemoteSignerInstance"`) |
| 签名前后 ELF 一致性 | `utils/src/compare_elf.cpp` | `compare_elf.h:34`（`shstrtab` 前后段/段表校验） |
| 错误码 | `hapsigntool_cpp/common/include/signature_tools_errno.h` | `:21`(`RET_OK=0`…`PROVISION_INVALID_ERROR=-117`) |
| 构建装配 | `BUILD.gn` + `signature_tools.gni` + 各子 `.gni` | `signature_tools.gni:14`(路径变量)、`BUILD.gn:42`(main_src 聚合) |

### 开始编辑前

1. 确认任务类别，按上表定位锚点
2. 涉及共享源时先确认是“本目录覆盖版”还是“复用 `hapsigntool_cpp` 版”（查对应 `signature_tools_*.gni` 的 `*_src` 清单）
3. 根据“项目约束”确认不违反任何约束
4. 声明：“我将修改 X，已读取 Y 锚点，遵循 Z 约束”

## 编码约定

- **4 空格**缩进禁 Tab；C++17（`-std=c++17`）、禁 RTTI（`-fno-rtti`）；不使用 C++ 异常。
- 命名空间 `OHOS::SignatureTools`；类名/方法 `PascalCase`（`SignElf`/`GetElfCodeSignBlock`），局部变量 `snake_case`/`camelCase` 混用，静态常量大写（`PAGE_SIZE`/`MAX_SECTION_SIZE`）。文件 `snake_case.cpp`；包含保护 `UPPER_SNAKE_CASE_H`。
- 头文件包含顺序：系统/OpenSSL 头 → `securec.h` → 工程头；ELF 处理统一经 `elfio.hpp`；JSON 经 `cJSON.h`。
- 内存：敏感缓冲区用 `securec.h` 的 `memset_s`/`memcpy_s`；`PasswordGuard` 析构先 `memset_s` 清零再 `delete[]`。OpenSSL 对象用 `X509_free`/`BIO_free`/`EVP_PKEY_free`/`sk_X509_pop_free` 配对释放，注意 `STACK_OF(X509)*` 的所有权（多处 `pop_free` 释放后仍被引用需谨慎）。
- 日志：`SIGNATURE_TOOLS_LOGE/LOGW/LOGI/LOGF` 始终输出；`LOGI/LOGD` 需定义 `SIGNATURE_LOG_DEBUG` 才编译。面向用户的提示用 `PrintMsg`（stdout）、错误用 `PrintErrorNumberMsg`（stderr，带错误码名+码+详情）。`SIGNATURE_LOG` 为 `printf` 宏，注意 `%` 格式串与可变参匹配。
- 参数模型：`Options` 继承 `unordered_map<string, variant<string,int,bool,char*>>`；命令行经 `CmdUtil::Convert2Params` 解析，`-key`/`value` 成对，重复键报错；密码类参数（键名以 `Pwd` 结尾）原样存 `char*`，其余转 `string`（`keyAlias`/`issuerKeyAlias` 强制小写）。合法参数集由 `ParamsTrustList` 解析 `HELP_TXT` 生成——**修改 help 文本即修改合法参数**。
- 错误码统一 `int` 负值（`signature_tools_errno.h`），函数返回 `bool` 或 `int`（`<0` 错）；`PrintErrorNumberMsg` 第一参为错误码变量名字符串。
- 签名算法仅支持 `SHA256withECDSA`/`SHA384withECDSA`（`constant.h:45`）；密钥长度 `NIST-P-256`/`NIST-P-384`。
- 测试：gtest，`class XxxTest : public testing::Test`；用例 `TEST_F`/`HWTEST_F`，资源放 `unittest/resource/`。

## 项目约束

### 安全关键约束（红线，改动必查）

**Do not（禁止）：**
- 在日志/`PrintMsg` 输出明文密码、私钥、keystore 内容、PIN。密码采集必须经 `PasswordGuard::getPasswordFromUser`（无回显 `termios`+30s `poll` 超时），用毕自动清零；`options` 中以 `char*` 形式存的 `*Pwd` 不得落盘或入日志。
- 绕过 `CmdUtil::UpdateParamForCheckInFile`/`UpdateParamForCheckOutFile` 直接信任用户传入路径：必须 `realpath` 归一化、`PATH_MAX` 校验、父目录存在性校验，防路径穿越/越界。
- 直接 `fopen` 读写 ELF：写签名段走 `SignElf::ReplaceDataOffset`（`fstream` 二进制）+ `FileUtils` 工具；输出文件若与输入同名先写 `*-tmp-signed` 再覆盖，并 `CopyPermissions` 保留原权限。
- 破坏 4K 对齐：`.codesign` 段必须 `set_addr_align(PAGE_SIZE)`、`csOffset % PAGE_SIZE == 0`，段大小为 `PAGE_SIZE` 整数倍（`verify_elf.cpp:87/97` 校验，内核 fs-verity 依赖）。
- 自签名（`selfSign=1`）路径误用证书链：`SelfSignSignProvider::SignElf` 用空 `SignerConfig`，签名取 `descriptorDigest`，**不生成 PKCS7/不带证书链**；改动不得让自签名走证书链分支，反之亦然。
- 远程签名器 so 来源不受控：`dlopen` 的插件路径来自 `-signerPlugin` 参数，`GetRemoteSignerInstance` 的 5 个 `RemoteSignerParamType`（keyAlias/signServer/onlineAuthMode/username/userPwd）ABI 不得擅自变更；`DynamicLibHandle::g_handle` 全局句柄需配对 `FreeHandle`。

**Ask before（修改前必须确认）：**
- 修改 `ElfSignInfo` 结构体字段顺序/大小/偏移（`verify_elf.h:30`）：与设备内核 fs-verity 校验、已签名 ELF 跨版本兼容性强相关。
- 修改 `ELF_CODE_SIGN_VERSION`、`FS_SHA256`/`FS_SHA512` 选择、`LOG_2_OF_FSVERITY_HASH_PAGE_SIZE`、`.codesign`/`.profile`/`.permission` 段名（`constant.h:91`）：影响板上验签与段识别。
- 修改 `RemoteSignerCreator` 函数指针签名或 `RemoteSignerParamType` 布局：远程签名器插件 ABI 兼容性。
- 修改 `help.h` 的 `HELP_TXT`：合法参数白名单由其派生，删/改参数名会直接影响命令行接受能力。
- 修改 `ownerID` 提取（`code_signing.cpp:127`，从叶子证书 `NID_organizationalUnitName` 取）：影响签名归属与验签匹配。

### 架构约束

- **双库复用模型**：`binary_sign_tool/` 与 `hapsigntool_cpp/` 经 `.gni` 共享大量源文件，部分文件（`sign_elf.cpp`/`bc_pkcs7_generator.cpp`/`fs_verity_generator.cpp`/`merkle_tree_builder.cpp`/`code_signing.cpp`/`profile_sign_tool.cpp`/`options.cpp`/`file_utils.cpp`/`compare_elf.cpp` 等）本目录有**覆盖版**。改动共享语义时须同步两套；仅改二进制签名专属逻辑时只动本目录覆盖版。
- **Provider 分轨与 CLI 可达性**：`SignToolServiceImpl::Sign` 按 `selfSign`→`localSign`→`remoteSign` 选择 provider。但 `help.h` 的 `HELP_TXT` 未含 `-mode`，`cmd_util.cpp:342` 硬置 `MODE=LOCAL_SIGN`，故 **`RemoteSignProvider`/`-signerPlugin` 代码路径在 CLI 下不可达**，实际仅 selfSign 与 localSign 可用（README 接口说明 列 `-mode` 与此不符）。三模式参数要求：local 必传 `keystoreFile`+`keyAlias`+`appCertFile` 且后缀 `p12`/`jks`（`params_run_tool.cpp:135`）；self（`-selfSign 1`）仅需 `inFile`+`outFile`+`selfSign`，在 `RunSignApp` 中于 localSign 必填校验之前提前 `return api.Sign`，**不生成证书链/PKCS7**，签名取 fs-verity `descriptorDigest`；remote 走 so 插件 + 可选 `appCertFile`。新增模式应扩展 `DISPATCH_RUN_METHOD`、`help.h` 与 provider，勿在现有分支硬编码。
- **签名总流程不可乱序**：`SignElf::Sign` 必须先删旧 `.codesign`/`.profile`/`.permission` → 写 profile/permission 段 → 写 4K `.codesign` 占位并 `save` → `CompareElf::Validate` → `GenerateCodeSignByte` 回填（此时 `csOffset` 已固定，fs-verity digest 计算排除 codesign 段）。回填前 `csOffset` 不确定则 digest 失真。
- **fs-verity 计算需排除已写段**：`MerkleTreeBuilder::SetCsOffset` 让哈希计算跳过 `.codesign` 段区域，改动不得让签名段自身参与根哈希计算（自引用）。
- **验签只读不写**：`VerifyElf` 仅解析 `.permission`(打印 JSON)/`.codesign`(解析 `ElfSignInfo`→`d2i_PKCS7`→`GetCertChains`→`X509_print_ex`)，不得修改输入 ELF。
