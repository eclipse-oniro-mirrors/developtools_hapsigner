# hapsigntool_cpp 组件指引（OpenHarmony hapsigner / hap-sign-tool）

> 本仓库面向 Agent 的指导文档统一使用中文；代码标识符、命令、路径、文件名保留原文。本工具为 C++17 主机侧 HAP/ELF/Bin/Profile 签名工具（可执行目标 `hap-sign-tool`），为 HAP（zip 容器）/ELF/`bin` 等产物提供 PKCS7/CMS 签名、fs-verity 代码签名块、profile `.p7b` 签名与全链路验签；签名后方可在真机设备运行/调试。属 `developtools` 子系统下 `hapsigner` 部件，基于 openharmony 标准系统 **ohos-sdk 形态**编译构建，使用前需先配置 openharmony 开发环境并使用 C++17 及以上语言标准。核心逻辑直接调用 OpenSSL（PKCS7/X509/EVP/CMS），无 HUKS/AlgLoader 抽象层；禁 RTTI（`-fno-rtti`），不使用异常（用 `do{}while(0)`+`goto err` 清理）。`main.cpp`（26 行）转交 `ParamsRunTool::ProcessCmd`，不加载 OpenSSL provider（依赖 OHOS 系统默认配置，与 `binary_sign_tool/main.cpp` 显式加载 default/legacy provider 不同）。共 11 个 CLI 命令（`sign-app`/`verify-app`/`sign-profile`/`verify-profile`/`resign-enterprise-app`/`generate-keypair`/`generate-ca`/`generate-cert`/`generate-csr`/`generate-app-cert`/`generate-profile-cert`）；签名算法仅支持 `SHA256withECDSA`/`SHA384withECDSA`，密钥长度 `NIST-P-256`/`NIST-P-384`。密钥库接受 `p12`/`jks`；支持交互式口令输入（`PasswordGuard` 无回显 `termios`+30s `poll` 超时）。本目录是 `binary_sign_tool/` 的**共享源码提供方**：`binary_sign_tool/` 经各 `signature_tools_*.gni` 聚合复用本目录 signer/common/utils/cmd/codesigning/profile/hap 的部分源文件，并对其中的 `sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp` 等提供覆盖版。

## 项目定位

本目录是 hapsigner 的**C++ 版 HAP/ELF/Bin/Profile 签名入口**，与 Java 版 `hapsigntool/`、原生 ELF 二进制签名 `binary_sign_tool/` 并列。三者共享签名格式规范（HAP 签名块 magic、block ID、fs-verity 常量、PKCS7/CMS 结构、ownerID OID）但代码独立；其中 `binary_sign_tool/` 经 `.gni` 直接复用本目录源文件（非链接库），形成"双库复用"关系。

优先按这些目录定位问题：

- `main.cpp`：进程入口（26 行），`int main` 直接调用 `ParamsRunTool::ProcessCmd(argv, argc)` 返回 0/1；不加载 OpenSSL provider（区别于 `binary_sign_tool/main.cpp` 显式 `OSSL_PROVIDER_load`）。
- `api/`：服务门面。`include/service_api.h` 抽象基类 `ServiceApi`（**11 个纯虚方法**：`GenerateKeyStore`/`GenerateCsr`/`GenerateCert`/`GenerateCA`/`GenerateAppCert`/`GenerateProfileCert`/`SignProfile`/`VerifyProfile`/`SignHap`/`ReSignHap`/`VerifyHapSigner`，注意：`binary_sign_tool` 的 `ServiceApi` 仅 `Sign`/`Verify` 两个方法，是本目录的子集覆盖版）。`src/sign_tool_service_impl.cpp`（740 行）是核心实现：`SignHap`（`:515`）按 `MODE` 选 provider、按 `INFORM` 分发 `Sign`/`SignElf`/`SignBin`；`SignProfile`（`:493`）调 `ProfileSignTool::GenerateP7b`；`VerifyHapSigner`（`:705`）按 `INFORM` 分发验签。`cert_tools.h/.cpp` 负责 CSR/X509 证书生成（仅 `SHA256withECDSA`/`SHA384withECDSA`，`cert_tools.cpp:443-453`）。
- `cmd/`：命令行解析与分发。`include/help.h`（358 行，**12 段 help 文本**组成 `HELP_TXT`，声明 11 个命令）；`src/params_run_tool.cpp`（655 行）含 `DISPATCH_RUN_METHOD`（`:40-47`，5 个 sign/verify 命令）与 `GENERATOR_RUN_METHOD`（`:49-57`，6 个 generate 命令）分发映射、`ProcessCmd`（`:60`）、`DispatchParams`（`:313`）、各 `Run*` 方法。`src/cmd_util.cpp`（536 行）做 `-key value` 解析（`Convert2Params` `:353`）、`realpath`+`PATH_MAX` 路径校验（`:179`/`:209`）、`keyAlias` 小写化（`:394`）。`src/params_trust_list.cpp` 由 `HELP_TXT` 运行时派生每命令合法参数白名单。`VERSION="1.0.0"`（`:27`）。`InformList={"bin","elf","zip"}`（`params_run_tool.h:34-38`）。
- `hap/`：HAP/ELF/Bin 签名/验签主体。`provider/`（`SignProvider` 基类 223 行头 + `LocalSignProvider`/`RemoteSignProvider`，`src/sign_provider.cpp` 1261+ 行为 HAP 签名总编排，含 Zip64 重试 `:1167`、权限签名 `:828-957`、代码签名 `:670`）；`sign/`（`SignHap`、`SignElf` **块追加格式** 非 ELF section、`SignBin`、`BCPkcs7Generator`、`Pkcs7Generator`）；`verify/`（`VerifyHap`、`VerifyElf`、`VerifyBin`）；`entity/`（`param_constants.h`、`signature_algorithm_helper.h`、`signature_block_tags.h`/`signature_block_types.h`、`block_data.h`/`block_head.h` 等 12 个头）；`utils/`（`hap_utils.h` block ID/magic、`dynamic_lib_handle.h` 远程签名器 so 句柄）；`config/`（`signer_config.h`）。
- `codesigning/`：fs-verity 生成。`fsverity/`（`FsVerityGenerator`、`MerkleTreeBuilder` 多线程 `Uscript::ThreadPool`、`FsVerityDescriptor` Builder 模式、`FsVerityHashAlgorithm`）；`sign/`（`CodeSigning` `GetCodeSignBlock` HAP 路径 `:46`/`GetElfCodeSignBlock` `:175`、`BCSignedDataGenerator` 带 ownerID OID、`SignedDataGenerator`、`VerifyCodeSignature`）；`datastructure/`（`CodeSignBlock`/`ElfSignBlock`/`HapInfoSegment`/`NativeLibInfoSegment`/`FsVerityInfoSegment`/`SignInfo` 等 12 头 12 源——**此目录不被 `binary_sign_tool` 编译**）；`utils/`（`CmsUtils`/`FsDigestUtils`/`DigestUtils`）。
- `profile/`：`profile_sign_tool.h/.cpp`（`GenerateP7b`/`SignProfile`）、`profile_info.h`（`ProfileInfo`+`BundleInfo`/`Acls`/`Permissions`/`DebugInfo`/`Validity`/`Metadata`/`ProvisionType`/`AppDistType`）、`profile_verify.h`（`ParseAndVerify`/`ParseProvision`/`ParseProfile` `DLL_EXPORT`）、`pkcs7_data.h`（`PKCS7Data` 类 `Sign`/`Parse`/`Verify`/`GetContent`/`SortX509Stack`，自定义 `std::hash<X509*>`/`std::equal_to<X509*>` 去重）。
- `signer/`：签名器抽象（**100% 被 `binary_sign_tool` 复用**）。`signer.h`（纯虚 `Signer`：`GetCrls`/`GetCertificates`/`GetSignature`）、`local_signer.h`（`LocalSigner` 持 `EVP_PKEY*`+`STACK_OF(X509)*`，`GetSignature` `:69` 用 `EVP_DigestSignInit/Update/Final`）、`signer_factory.h`（`GetSigner` + `RemoteSignerParamType` 结构体 + `RemoteSignerCreator` 函数指针 typedef，5 参数 ABI）、`src/signer_factory.cpp`（`LoadRemoteSigner` `:42` `dlopen`+`dlsym "GetRemoteSignerInstance"`，用 `DynamicLibHandle::g_handle` 全局句柄）。
- `common/`：`options.h`（`Options : public unordered_map<string, variant<string,int,bool,char*>>`，34 个静态键常量，`GetChars`/`GetString`/`GetInt`/`GetBool`）、`constant.h`（命令名/算法名/OID 常量，`OWNERID_OID="1.3.6.1.4.1.2011.2.376.1.4.1"` `:55`，签名能力字节数组 `:24-25`，**`:92` 命名空间注释误写为 `UpdateEngine` 应为 `SignatureTools`**）、`signature_tools_errno.h`（`RET_OK=0`…`PROVISION_INVALID_ERROR=-117`，17 码）、`signature_tools_log.h`（`SIGNATURE_LOG` 宏=printf，`LOGE/LOGF` 常开、`LOGI/LOGD/LOGW` 需 `SIGNATURE_LOG_DEBUG`、`PrintErrorNumberMsg`→stderr、`PrintMsg`→stdout）、`password_guard.h/.cpp`（`termios`+`poll` 30s 无回显口令，`clear()` 先 `memset_s` 再 `delete[]`，包含保护为 `PASSWORD_GUARD_H` 无 OHOS 前缀）、`byte_buffer.h`（Java-NIO 风格 `DLL_EXPORT`）、`localization_adapter.h`（桥接 Options↔OpenSSL，`GetAliasKey`/`ResetPwd`）、`export_define.h`（`DLL_EXPORT`/`DLL_LOCAL`）、`pkcs7_context.h`、`digest_common.h`/`digest_parameter.h`、`data_source.h`/`byte_buffer_data_source.h`/`file_data_source.h`/`random_access_file.h`。
- `utils/`：`key_store_helper.h/.cpp`（PKCS12 create/verify/read，`GenerateKeyPair`，NID `NID_PBE_CBC=149`/`NID_TRIPLEDES_CBC=146`）、`file_utils.h`（`IsEmpty`/`GetSuffix`/`ValidFileType`/`IsValidFile`/`Write`/`Read`/`ReadFile`/`AppendWriteFileByOffsetToFile`/`IsRunnableFile`/`GetFileLen`/`DelDir`）、`hap_signer_block_utils.h`（HAP 块解析/构建，`HapBlobType` 枚举 `:44-51`，magic `HAP_SIG_BLOCK_MAGIC_HIGH/LOW`，`FindHapSignature`/`VerifyHapIntegrity`/`FindEocdInHap`，`MAX_HAP_SIGN_BLOCK_SIZE=1024MB` `:78`）、`signature_info.h`（`OptionalBlock`/`SignatureInfo`）、`byte_array_utils.h`/`cert_dn_utils.h`/`hash_utils.h`/`string_utils.h`/`verify_cert_openssl_utils.h`/`verify_hap_openssl_utils.h`。
- `zip/`：**完整 ZIP 读写（14 头 13 源），`binary_sign_tool` 无此目录**。`ZipSigner`、`ZipEntry`/`ZipEntryData`/`ZipEntryHeader`、`CentralDirectory`、`EndOfCentralDirectory`、`Zip64EndOfCentralDirectory`/`Locator`/`ExtendedInfo`、`DataDescriptor`、`RandomAccessFileInput`/`Output`、`ZipDataInput`、`ZipUtils`。用途：HAP/zip 签名——读 EOCD/Zip64、在 central directory 前插入签名块、重写偏移。
- `hapsigntool_cpp_test/`（兄弟目录）：gtest 单测 + fuzz，见"构建和验证"。

### 按任务类型定位代码

| 任务类型 | 目标位置 | 关键锚点 |
| --- | --- | --- |
| CLI 命令分发 | `cmd/src/params_run_tool.cpp` | `:60`(`ProcessCmd`)、`:313`(`DispatchParams`)、`:40`(`DISPATCH_RUN_METHOD` sign/verify)、`:49`(`GENERATOR_RUN_METHOD` generate) |
| CLI 参数解析/校验 | `cmd/src/cmd_util.cpp` + `cmd/src/params_trust_list.cpp` + `cmd/include/help.h` | `cmd_util.cpp:353`(`Convert2Params`)、`:179`/`:209`(realpath 路径校验)、`:394`(keyAlias 小写)；`params_trust_list.cpp`(`GetTrustList` 由 `HELP_TXT` 派生)；`help.h:27-29`(USAGE) |
| HAP(zip) 签名 | `api/src/sign_tool_service_impl.cpp` + `hap/provider/src/sign_provider.cpp` + `hap/sign/src/sign_hap.cpp` | `sign_tool_service_impl.cpp:515`(`SignHap`)、`:527`/`:531`/`:535`(INFORM 分发)；`sign_provider.cpp:327`(`Sign`) |
| ELF 签名 | `hap/sign/src/sign_elf.cpp` + `hap/provider/src/sign_provider.cpp` | `sign_provider.cpp:495`(`SignElf`)；`sign_elf.h:34`(`CODESIGN_BLOCK_TYPE=3`)、`:40`(`PAGE_SIZE=4096`) |
| Bin 签名 | `hap/provider/src/sign_provider.cpp` + `hap/sign/src/sign_bin.cpp` | `sign_provider.cpp:542`(`SignBin`) |
| 验签（HAP/ELF/Bin） | `api/src/sign_tool_service_impl.cpp` + `hap/verify/` | `sign_tool_service_impl.cpp:705`(`VerifyHapSigner`)；`verify_hap.cpp`/`verify_elf.cpp`/`verify_bin.cpp` |
| profile `.p7b` 生成 | `api/src/sign_tool_service_impl.cpp` + `profile/src/profile_sign_tool.cpp` | `sign_tool_service_impl.cpp:493`(`SignProfile`) |
| profile 校验/解析 | `profile/src/profile_verify.cpp` + `profile/include/profile_info.h` | `profile_verify.h`(`ParseAndVerify`/`ParseProvision`) |
| 密钥库 p12/jks | `utils/src/key_store_helper.cpp` + `utils/include/key_store_helper.h` | `key_store_helper.h`(`WriteKeyStore`/`VerifyKeyStore`/`ReadKeyStore`/`CreatePKCS12`/`GenerateKeyPair`) |
| PKCS7/CMS 生成 | `hap/sign/src/bc_pkcs7_generator.cpp` + `codesigning/sign/src/bc_signeddata_generator.cpp` + `profile/src/pkcs7_data.cpp` | `bc_pkcs7_generator.cpp`(`BCPkcs7Generator`)；`bc_signeddata_generator.cpp`(带 ownerID OID) |
| fs-verity Merkle 树/digest/描述符 | `codesigning/fsverity/` | `merkle_tree_builder.cpp`(`GenerateMerkleTree`)；`fs_verity_generator.cpp`(`GenerateFsVerityDigest`)；`fs_verity_descriptor.h:29-38`(VERSION=1/DESCRIPTOR_SIZE=256/PAGE_SIZE_4K=4096) |
| 代码签名块（HAP） | `codesigning/sign/src/code_signing.cpp` | `:46`(`GetCodeSignBlock`，HAP 多段) |
| 代码签名块（ELF） | `codesigning/sign/src/code_signing.cpp` | `:175`(`GetElfCodeSignBlock`，`ElfSignBlock`+`FsVerityDescriptorWithSign`；**`:192` 有拼写错误 `"DEBUF_LIB_ID"` 应为 `DEBUG_LIB_ID`**) |
| 远程签名器插件 ABI | `signer/include/signer_factory.h` + `signer/src/signer_factory.cpp` | `signer_factory.h:27-36`(`RemoteSignerParamType`+`RemoteSignerCreator`，5 参数)；`signer_factory.cpp:42`(`LoadRemoteSigner` dlopen)、`:65`(dlsym "GetRemoteSignerInstance") |
| 错误码 | `common/include/signature_tools_errno.h` | `:21`(`RET_OK=0`…`PROVISION_INVALID_ERROR=-117`) |
| 日志 | `common/include/signature_tools_log.h` | `:35`(`SIGNATURE_LOG`=printf)；`:38`(LOGE/LOGF 常开、LOGI/LOGD/LOGW 需 `SIGNATURE_LOG_DEBUG`) |
| 参数模型 | `common/include/options.h` | `:28`(`Options : public unordered_map`)；34 键常量 |
| ZIP 容器操作 | `zip/src/zip_signer.cpp` + `zip/` 全目录 | `ZipSigner`；`zip64_end_of_central_directory.cpp` |
| HAP 块 magic/ID | `hap/utils/include/hap_utils.h` | `:53-65`(block ID)、`:75-78`(magic V2/V3) |
| 构建装配 | `BUILD.gn` + `signature_tools.gni` + 各子 `.gni` | `BUILD.gn:58`(`ohos_executable`)、`:85-88`(openssl shared)、`:90-94`(c_utils/cJSON/zlib)、`:96-104`(-std=c++17 -fno-rtti) |

### 命令行参数（CLI 实况）

> 受信参数由 `help.h` 的 `HELP_TXT` 经 `ParamsTrustList::GetTrustList` 运行时派生，**修改 help.h 即修改合法参数集**。`CmdUtil::Convert2Params`（`cmd_util.cpp:353`）以 `-key value` 成对解析；`UpdateParamForCheckInFile`/`UpdateParamForCheckOutFile`（`:179`/`:209`）对路径做 `realpath`+`PATH_MAX` 校验；`TransformKeyAliasWhenLocalSign`（`:394`）对 `keyAlias` 强制小写。

- 11 命令见 `help.h:27-29`/`:338-350`：`sign-app`/`verify-app`/`sign-profile`/`verify-profile`/`resign-enterprise-app`/`generate-keypair`/`generate-ca`/`generate-cert`/`generate-csr`/`generate-app-cert`/`generate-profile-cert`。
- `sign-app`（`RunSignApp` `params_run_tool.cpp:186`）：`mode` 受限 `localSign`/`remoteSign`（**与 `binary_sign_tool` 不同：本目录 help.h 含 `-mode`，`RemoteSignProvider` 在 CLI 下可达**）；`inForm` 默认 `zip`，受限于 `InformList={"bin","elf","zip"}`（`params_run_tool.h:34-38`，`binary_sign_tool` 无 `InformList` 且仅 ELF）；签名算法 `SHA256withECDSA`/`SHA384withECDSA`；HAP 签名另有 `-signCode`/`-permSign`/`-compatibleVersion`。
- `sign-profile`（`RunSignProfile` `:543`）：`mode` `localSign`/`remoteSign`；输入 `.json`（未签名）或 `.p7b`（已签名），输出 `.p7b`。
- `verify-app`/`verify-profile`（`:626`/`:589`）。
- `resign-enterprise-app`（`RunReSignApp` `:239`）：仅 `.hap` zip。
- `generate-*`（`:485` RunKeypair / `:512` RunCsr / `:360` RunCert / `:326` RunCa / `:443` RunAppCert / `:464` RunProfileCert）。
- 口令交互：经 `PasswordGuard`（`password_guard.h`，`termios` 无回显 + `poll` 30s 超时），`params_run_tool.cpp:29-33` 有 5 个全局 `PasswordGuard` 实例。
- **与 `binary_sign_tool` CLI 差异**：本目录有 11 命令（彼 2 个 `sign`/`display-sign`）；本目录无 `-selfSign`/`-moduleFile`（彼专有）；本目录 `-mode` 可达 remoteSign（彼硬置 `MODE=LOCAL_SIGN`，remoteSign 不可达）；本目录 `inForm` 支持 zip/elf/bin（彼仅 ELF）。

## 构建和验证

构建在 OpenHarmony 源码根目录执行，不在本子目录执行。

1. 编译 ohos-sdk 形态签名工具：
   + **release** 版本：默认即 release，直接编译。
   + **debug** 版本（增加调试日志）：在 `hapsigntool_cpp/BUILD.gn` 中添加 `defines = [ "SIGNATURE_LOG_DEBUG" ]` 即可（该宏控制 `SIGNATURE_TOOLS_LOGI/LOGD` 是否编译，见 `common/include/signature_tools_log.h:38`）。
2. 编译命令：

```bash
./build.sh --product-name ohos-sdk
```

3. 编译产物路径：`/openharmony_master/out/sdk/packages/ohos-sdk`（可执行 `hap-sign-tool`）。`BUILD.gn:25-41` 的 `ohos_copy("copy_signature_tools_resource")` 另把 `../dist/`（`OpenHarmony.p12`/`OpenHarmonyApplication.pem`/`OpenHarmonyProfileDebug.pem`/`OpenHarmonyProfileRelease.pem`/`*.p7b`/`*.json` 模板）拷到 `toolchains/hapsigntool_pc/`。

**编译装配与依赖**（`hapsigntool_cpp/BUILD.gn`）：`ohos_executable("hap-sign-tool")`（`:58`，**单目标，无 shared/static library**）经 `signature_tools.gni`（`:14` 路径变量）聚合 7 子 `.gni`（cmd/codesigning/common/hap/profile/utils/**zip**）。`signature_tools_main_src`（`:50-56`）= `main.cpp` + `api/src/sign_tool_service_impl.cpp` + `api/src/cert_tools.cpp` + `signer/src/signer_factory.cpp` + `signer/src/local_signer.cpp`。外部依赖：`deps` = `openssl:libcrypto_shared`+`openssl:libssl_shared`（**shared**，`:85-88`，区别于 `binary_sign_tool` 用 static）；`external_deps` = `c_utils:utils`、`cJSON:cjson_static`、`zlib:shared_libz`（`:90-94`，区别于 `binary_sign_tool` 用 elfio+bounds_checking_function 无 zlib/c_utils）。编译选项 `-std=c++17 -fno-rtti -Wno-c++20-extensions`（`:96-104`，**无 `remove_configs`**，区别于 `binary_sign_tool` 移除 `//build/config:executable_config`）。`install_enable=false`、`install_images=["system"]`、`part_name="hapsigner"`、`subsystem_name="developtools"`。`bundle.json`（`:24-30`）声明 component `hapsigner`、subsystem `developtools`；deps 含 `bounds_checking_function/c_utils/cJSON/elfio/openssl/zlib/hilog`（注：`elfio`/`hilog` 列于 bundle.json 但 `BUILD.gn` 未直接引用——`elfio` 实为 `binary_sign_tool` 的 `compare_elf.cpp` 所用）。

测试位于兄弟目录 `hapsigntool_cpp_test/`（gtest，`bundle.json:53-54`：`hapsigntool_cpp_test/unittest:hapsigntool_pc_unittest` + `hapsigntool_cpp_test/fuzztest:hapsigntool_pc_fuzztest`）。测试工程引用本目录的 `.gni`，`--coverage` 编译，链接 openssl shared + `cJSON`/`zlib`/`hilog`/`c_utils`。编译后过滤执行：

```bash
out/<product>/.../hapsigntool_pc_unittest --gtest_filter=SignHapTest.*
out/<product>/.../hapsigntool_pc_unittest --gtest_filter=VerifyElfTest.*
```

> 注意：单测工程的 `.gni` 源文件清单与 `binary_sign_tool/` 的 `.gni` 略有差异（`binary_sign_tool` 额外含本目录覆盖版 `sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp` 等、`compare_elf.cpp`、`self_sign_sign_provider.cpp`，且不含 `zip/` 与 `codesigning/datastructure/`），同步两套实现时需双向核对。

静态检查：OpenHarmony 构建链集成静态分析工具（`cppcheck` 等），可对改动文件跑 `cppcheck --enable=warning,style <file>`；C/C++ 编译告警选项随构建链启用，改动不得引入新增告警或抬升告警级别。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已完成** - `git commit -s`
2. **本地构建通过** - `./build.sh --product-name ohos-sdk` 编译成功，产物位于 `/openharmony_master/out/sdk/packages/ohos-sdk`
3. **相关测试通过** - 受影响的 gtest 目标执行并提供输出摘要
4. **共享代码双向核对** - 同时触及本目录与 `binary_sign_tool/` 同名实现时，确认两处语义一致（`binary_sign_tool` 的部分源文件以覆盖/重写形式参与编译，见各 `.gni`；本目录是源码提供方，改共享语义须同步覆盖版）
5. **安全清单逐条核对** - 见"项目约束→安全关键约束"

### 如果无法运行验证

说明原因（如需真实 keystore/`.p12` 证书链、远程签名器 so 插件、板侧 fs-verity 内核能力），列出推荐验证步骤与预期输出关键字供人工执行，不得声称已验证。

### 完成报告格式

改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（HAP 块布局/签名格式兼容性、密钥与密码安全、ELF/zip 块格式、跨版本）、未完成事项。

## 知识索引

本目录暂无独立 `docs/knowledge/`，稳定背景知识以代码与常量定义为准，改动前按场景读取：

| 场景 | 修改位置 | 先读锚点 |
| --- | --- | --- |
| 命令/help 文本/受信参数 | `cmd/` | `help.h:27-29`(USAGE)、`params_trust_list.cpp`(`GetTrustList` 由 `HELP_TXT` 派生，**改 help 即改合法参数集**)、`cmd_util.cpp:353`(`Convert2Params`) |
| 签名总流程 | `api/` + `hap/provider/` + `hap/sign/` | `sign_tool_service_impl.cpp:515`(`SignHap`)、`:527`/`:531`/`:535`(INFORM 分发)；`sign_provider.cpp:327`(`Sign` 编排) |
| HAP 签名块 magic/ID | `hap/utils/include/hap_utils.h` | `:53-65`(block ID)、`:75-78`(magic V2/V3)、`MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3=8` |
| ELF 块格式（非 section） | `hap/sign/include/sign_elf.h` + `hap/verify/include/verify_elf.h` | `sign_elf.h:34`(`CODESIGN_BLOCK_TYPE=3`)、`:40`(`PAGE_SIZE=4096`)、`:30`(`CODESIGN_OFF="0"`)；`verify_elf.h:32-36`(block 类型枚举) |
| fs-verity 描述符/digest/Merkle | `codesigning/fsverity/` | `fs_verity_descriptor.h:29-38`(VERSION=1/DESCRIPTOR_SIZE=256/ROOT_HASH_FILED_SIZE=64/SALT_SIZE=32/PAGE_SIZE_4K=4096)；`code_signing.cpp:33-35`(`FS_SHA256`=1/`FS_SHA512`=2/`LOG_2_OF_FSVERITY_HASH_PAGE_SIZE`=12→4096 页) |
| 代码签名块（HAP/ELF） | `codesigning/sign/src/code_signing.cpp` + `codesigning/datastructure/` | `:46`(`GetCodeSignBlock` HAP)、`:175`(`GetElfCodeSignBlock` ELF)、`:69`(ownerID 从 provision 提取)；`elf_sign_block.h:29`(`MERKLE_TREE_INLINED=0x2`)、`sign_info.h:32`(`FLAG_MERKLE_TREE_INCLUDED=0x1`) |
| PKCS7/CMS | `hap/sign/src/bc_pkcs7_generator.cpp` + `codesigning/sign/src/bc_signeddata_generator.cpp` + `profile/src/pkcs7_data.cpp` | `bc_signeddata_generator.cpp`(`AddOwnerID`，`OWNERID_OID` 见 `constant.h:55`)；`pkcs7_data.h:60-61`(`PKCS7_NODETACHED_FLAGS`/`PKCS7_DETACHED_FLAGS`) |
| profile 校验/解析 | `profile/` | `profile_verify.h`(`ParseAndVerify`/`ParseProvision`)；`profile_info.h`(`ProfileInfo`+`ProvisionType`/`AppDistType`) |
| 远程签名器插件 ABI | `signer/include/signer_factory.h` + `signer/src/signer_factory.cpp` | `:27-36`(`RemoteSignerParamType`+`RemoteSignerCreator`，5 参数：keyAlias/signServer/onlineAuthMode/username/userPwd)、`:65`(dlsym "GetRemoteSignerInstance")；`hap/utils/include/dynamic_lib_handle.h`(`g_handle` 全局句柄) |
| 密钥库/口令 | `utils/` + `common/include/password_guard.h` | `key_store_helper.h`(`CreatePKCS12`/`VerifyKeyStore`/`ReadKeyStore`，`NID_PBE_CBC=149`/`NID_TRIPLEDES_CBC=146`)；`password_guard.cpp:47`(`clear()` 先 `memset_s` 再 `delete[]`)、`:34`(`termios`+`poll` 30s) |
| 错误码 | `common/include/signature_tools_errno.h` | `:21`(`RET_OK=0`…`PROVISION_INVALID_ERROR=-117`) |
| 构建装配 | `BUILD.gn` + `signature_tools.gni` + 各子 `.gni` | `signature_tools.gni:14`(路径变量)、`BUILD.gn:58`(`ohos_executable`)、`:85-88`(openssl shared)、`:90-94`(c_utils/cJSON/zlib)、`:96-104`(cflags) |

### 词汇路由

任务/日志/issue/API 中若出现下列域词，先命中"知识索引"对应行再编辑：

| 域词 | 命中"知识索引"行 |
| --- | --- |
| `HAP Sig Block 42` / `<hap sign block>` / magic V2/V3 / block ID / `HapBlobType` | HAP 块 magic/ID |
| `fs-verity` / Merkle 树 / `FS_SHA256`/`FS_SHA512` / `PAGE_SIZE_4K` / 4K 对齐 | fs-verity 描述符/digest/Merkle、代码签名块（HAP/ELF） |
| `ownerID OID`（`1.3.6.1.4.1.2011.2.376.1.4.1`）/ `BCSignedDataGenerator` / `AddOwnerID` | PKCS7/CMS（触发与 Java/binary_sign_tool 三向核对） |
| `ElfSignBlock` / `CODESIGN_BLOCK_TYPE=3` / `CODESIGN_OFF` / `.codesign` | ELF 块格式（非 section）——注意本目录块追加格式与 `binary_sign_tool` 的 ELF section 格式**不兼容** |
| `ServiceApi` / 11 纯虚方法 | 远程签名器插件 ABI（见"项目约束→Ask before"） |
| `RemoteSignerCreator` / `RemoteSignerParamType` / `GetRemoteSignerInstance` / so 插件 | 远程签名器插件 ABI（`binary_sign_tool` 100% 复用此 ABI） |
| `HELP_TXT` / `ParamsTrustList` / `help.h` / 受信参数 | 命令/help 文本/受信参数（**改 help 即改合法参数集**） |
| `PasswordGuard` / `termios` / `poll` / `*Pwd` | 密钥库/口令（见安全关键约束） |
| `realpath` / `PATH_MAX` / `UpdateParamForCheckInFile` | 路径校验（见安全关键约束） |
| `sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp` 等覆盖版 | 见"开始编辑前"第 2 条——先判定是本目录版还是 `binary_sign_tool` 覆盖版 |

### 开始编辑前

1. 确认任务类别，按上表定位锚点
2. 涉及共享源时先确认是"本目录版"还是"`binary_sign_tool` 覆盖版"（查 `binary_sign_tool/` 对应 `signature_tools_*.gni` 的 `*_src` 清单——`binary_sign_tool` 覆盖 `sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp`/`merkle_tree_builder.cpp`/`bc_pkcs7_generator.cpp`/`profile_sign_tool.cpp`/`profile_info.cpp`/`options.cpp`/`file_utils.cpp` 等，并新增 `compare_elf.cpp`/`self_sign_sign_provider.cpp`，且不含 `zip/` 与 `codesigning/datastructure/`）
3. 根据"项目约束"确认不违反任何约束
4. 声明："修改目标：X；已读锚点：Y；遵循约束：Z"

## 编码约定

- **4 空格**缩进禁 Tab；C++17（`-std=c++17`）、禁 RTTI（`-fno-rtti`）；不使用 C++ 异常（用 `do{}while(0)`+`break`+`goto err` 清理模式）。
- 命名空间 `OHOS::SignatureTools`；类名/方法 `PascalCase`（`SignElf`/`GetCodeSignBlock`/`FsVerityGenerator`）；局部变量 `snake_case`/`camelCase` 混用；静态常量大写（`PAGE_SIZE`/`MAX_SECTION_SIZE`）。文件 `snake_case.cpp`；包含保护 `UPPER_SNAKE_CASE_H`（多数写为 `SIGNATRUETOOLS_*_H`——注意拼写错误"SIGNATRUETOOLS"应为"SIGNATURETOOLS"，已有大量文件沿用，勿单独"修正"破坏一致性；**`password_guard.h` 例外用 `PASSWORD_GUARD_H` 无 OHOS 前缀**）。
- 头文件包含顺序：系统/STL → OpenSSL 头 → `securec.h`（使用处）→ 工程头；ELF 处理经 `elfio.hpp`（仅在 `binary_sign_tool` 覆盖版，本目录 ELF 用块追加格式不依赖 elfio）；JSON 经 `cJSON.h`。
- 内存：敏感缓冲区用 `securec.h` 的 `memset_s`/`memcpy_s`；`PasswordGuard` 析构先 `memset_s` 清零再 `delete[]`（`password_guard.cpp:47`）。OpenSSL 对象用 `X509_free`/`BIO_free`/`EVP_PKEY_free`/`X509_REQ_free`/`ASN1_INTEGER_free`/`sk_X509_pop_free` 配对释放，注意 `STACK_OF(X509)*` 的所有权（多处 `pop_free` 释放后仍被引用需谨慎）。`do{}while(0)`+`break`+`goto err` 清理模式。
- 日志：`SIGNATURE_TOOLS_LOGE/LOGF` 始终输出；`LOGI/LOGD/LOGW` 需定义 `SIGNATURE_LOG_DEBUG` 才编译（`signature_tools_log.h:38`）。面向用户的提示用 `PrintMsg`（stdout）、错误用 `PrintErrorNumberMsg(name, code, details)`（stderr，带错误码名+码+详情）。`SIGNATURE_LOG` 为 `printf` 宏（`:35`），注意 `%` 格式串与可变参匹配。
- 参数模型：`Options` 继承 `unordered_map<string, variant<string,int,bool,char*>>`（`options.h:28`）；命令行经 `CmdUtil::Convert2Params`（`cmd_util.cpp:353`）解析，`-key`/`value` 成对；密码类参数（键名以 `Pwd` 结尾）原样存 `char*`，`keyAlias` 强制小写（`cmd_util.cpp:394`）。合法参数集由 `ParamsTrustList` 解析 `HELP_TXT` 生成——**修改 help 文本即修改合法参数**。
- 错误码统一 `int` 负值（`signature_tools_errno.h`，17 码 0 至 -117），函数返回 `bool` 或 `int`（`<0` 错）；`PrintErrorNumberMsg` 第一参为错误码变量名字符串。
- 签名算法仅支持 `SHA256withECDSA`/`SHA384withECDSA`（`constant.h:45-46`）；密钥长度 `NIST-P-256`/`NIST-P-384`（`constant.h:31-32`）。`SignProvider::VALID_SIGN_ALG_NAME` 另列 `SHA512withECDSA`（`sign_provider.cpp:44`）但证书生成路径不支持。
- 测试：gtest，`class XxxTest : public testing::Test`；用例 `TEST_F`/`HWTEST_F`，位于兄弟目录 `hapsigntool_cpp_test/`。

## 项目约束

### 安全关键约束（红线，改动必查）

**Do not（禁止）：**
- 在日志/`PrintMsg` 输出明文口令、私钥、keystore 内容：口令采集必须经 `PasswordGuard`（无回显 `termios`+30s `poll` 超时，`password_guard.cpp:34`），用毕 `clear()` 先 `memset_s` 再 `delete[]`（`:47`）；`options` 中以 `char*` 形式存的 `*Pwd` 不得落盘或入日志；`LocalizationAdapter::ResetPwd()` 用毕清零（`sign_tool_service_impl.cpp` 多处调用）。
- 绕过 `CmdUtil::UpdateParamForCheckInFile`/`UpdateParamForCheckOutFile`（`cmd_util.cpp:179`/`:209`）直接信任用户传入路径：必须 `realpath` 归一化、`PATH_MAX` 校验、父目录存在性校验，防路径穿越/越界。
- 破坏 HAP 签名块字节格式：block ID（`hap_utils.h:53-65`，`HAP_SIGNATURE_SCHEME_V1_BLOCK_ID=0x20000000`/`HAP_CODE_SIGN_BLOCK_ID=0x30000001`/`PERMISSION_SIGN_BLOCK_ID=0x30000002`）、magic（`:75-78`，V2 lo/hi `0x2067695320504148`/`0x3234206b636f6c42`、V3 `0x676973207061683c`/`0x3e6b636f6c62206e`）、`MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3=8`、权限摘要类型（`:62-65` PROVISION=1/MODULE_JSON=2/CODE_SIGN_BLOCK=3/SHARED_FILE=4，`MAX_PERMISSION_SIGN_DIGEST_COUNT=4`）、`MAX_HAP_SIGN_BLOCK_SIZE=1024MB`（`hap_signer_block_utils.h:78`）均为设备端验签强依赖。
- 破坏 4K 对齐：`SignElf::PAGE_SIZE=4096`（`sign_elf.h:40`）、`AlignFileBy4kBytes` 填充（`sign_elf.cpp:98-100`）、`CodeSignBlock::PAGE_SIZE_4K=4096`、`FsVerityDescriptor::PAGE_SIZE_4K=4096`、`ComputeDataSize` 强制 `dataSize%4096==0`（`code_signing.cpp:118`）——内核 fs-verity 依赖。
- 破坏 fs-verity 常量：`FsVerityDescriptor::VERSION=1`/`CODE_SIGN_VERSION=0x1`/`DESCRIPTOR_SIZE=256`/`ROOT_HASH_FILED_SIZE=64`/`SALT_SIZE=32`/`FLAG_STORE_MERKLE_TREE_OFFSET=0x1`（`fs_verity_descriptor.h:29-38`）、`FS_SHA256`(id=1)/`FS_SHA512`(id=2)（`code_signing.cpp:33-34`）、`LOG_2_OF_FSVERITY_HASH_PAGE_SIZE=12`（→4096 页，`code_signing.cpp:35`）——须与内核 fs-verity 规范一致。
- 随意接受任意签名算法/密钥长度：证书生成仅 `SHA256withECDSA`/`SHA384withECDSA`（`cert_tools.cpp:443-453`）、密钥 `NIST-P-256`/`NIST-P-384`（`constant.h:31-32`）。
- 信任不受控的远程签名器 so：`dlopen` 的插件路径来自 `-signerPlugin` 参数，`GetRemoteSignerInstance` 的 5 个 `RemoteSignerParamType`（keyAlias/signServer/onlineAuthMode/username/userPwd）ABI（`signer_factory.h:27-36`）不得擅自变更；`DynamicLibHandle::g_handle` 全局句柄需配对 `FreeHandle`。
- 随意修改 ELF 块格式：`SignElf::CODESIGN_BLOCK_TYPE=3`（`sign_elf.h:34`）、`ElfSignBlock::MERKLE_TREE_INLINED=0x2`（`elf_sign_block.h:29`）、`SignInfo::FLAG_MERKLE_TREE_INCLUDED=0x1`（`sign_info.h:32`）、`CODESIGN_OFF="0"`（`sign_elf.h:30`）——设备验签依赖。

**Ask before（修改前必须确认）：**
- 修改 `ServiceApi` 接口（`service_api.h`，11 纯虚方法）：构成对外抽象基类，`SignToolServiceImpl` 与 `binary_sign_tool` 的覆盖版均依赖。
- 修改 `ElfSignInfo`/`SignInfo` 结构体字段顺序/大小/偏移：与设备内核 fs-verity 校验、已签名文件跨版本兼容性强相关。
- 修改 `CODE_SIGN_VERSION`、`FS_SHA256`/`FS_SHA512` 选择、`LOG_2_OF_FSVERITY_HASH_PAGE_SIZE`、block 类型常量：影响板上验签与块识别。
- 修改 `RemoteSignerCreator` 函数指针签名或 `RemoteSignerParamType` 布局（`signer_factory.h:27-36`）：远程签名器插件 ABI 兼容性（`binary_sign_tool` 100% 复用此 ABI）。
- 修改 `help.h` 的 `HELP_TXT`：合法参数白名单由其派生，删/改参数名会直接影响命令行接受能力。
- 修改 `OWNERID_OID`（`constant.h:55`，`"1.3.6.1.4.1.2011.2.376.1.4.1"`）或 ownerID 提取逻辑（`code_signing.cpp:69`）：影响签名归属与验签匹配。
- 修改 `constant.h` 签名能力字节数组（`:24-25`，`APP_SIGNING_CAPABILITY`/`PROFILE_SIGNING_CAPABILITY`）：影响证书签发能力识别。
- 升级第三方依赖（`openssl`/`cJSON`/`zlib`/`elfio`/`c_utils` 等）版本：须核对 license 兼容性与签名字节兼容性，不得静默升版；版本经 `bundle.json:24-30` 的 deps 与 `BUILD.gn:85-94` 的 `external_deps` 声明，shared/static 切换（如 openssl shared→static）会影响 `binary_sign_tool` 的链接模型。

### 架构约束

- **双库复用模型**：本目录是源码提供方，`binary_sign_tool/` 经 `.gni` 聚合复用本目录 signer/common/utils/cmd/codesigning/profile/hap 的部分源文件。`binary_sign_tool/` 对其中 `sign_elf.cpp`/`code_signing.cpp`/`fs_verity_generator.cpp`/`merkle_tree_builder.cpp`/`fs_verity_descriptor.cpp`/`bc_pkcs7_generator.cpp`/`profile_sign_tool.cpp`/`profile_info.cpp`/`options.cpp`/`file_utils.cpp` 等提供**覆盖版**，并新增 `compare_elf.cpp`/`self_sign_sign_provider.cpp`；**不编译**本目录的 `zip/` 与 `codesigning/datastructure/`。改动共享语义时须同步两套；仅改 HAP/zip/profile 专属逻辑时只动本目录；仅改 ELF 二进制签名专属逻辑时只动 `binary_sign_tool` 覆盖版。
- **Provider 分轨与 CLI 可达性**：`SignToolServiceImpl::SignHap`（`:515`）按 `MODE`(`localSign`/`remoteSign`) 选 `LocalSignProvider`/`RemoteSignProvider`，按 `INFORM`(`zip`/`elf`/`bin`) 分发 `Sign`/`SignElf`/`SignBin`（`:527`/`:531`/`:535`）。**本目录 help.h 含 `-mode`，`RemoteSignProvider` 在 CLI 下可达**（区别于 `binary_sign_tool` 硬置 `MODE=LOCAL_SIGN` 致 remoteSign 不可达）。`signer/` 100% 被 `binary_sign_tool` 复用，`LocalSigner` 用 `EVP_DigestSignInit/Update/Final`（`local_signer.cpp:69`），`RemoteSigner` 经 so 插件加载。
- **ELF 签名采用块追加格式而非 ELF section**：`SignElf::Sign` 追加 `blockHead`+`signBlockList`+`signHead` 到文件（`sign_elf.h:34` `CODESIGN_BLOCK_TYPE=3`，`:40` `PAGE_SIZE=4096`，`:30` `CODESIGN_OFF="0"`），与 `binary_sign_tool` 用 `elfio` 写真实 ELF section（`.codesign`/`.profile`/`.permission`）的模型**不同**——两者 ELF 签名格式互不兼容，改一处勿误以为另一处一致。
- **签名总流程不可乱序**：`SignProvider::Sign`（`:327`）必须 IO streams → `ZipSigner` → `InitDataSourceContents` → `DoSignBlock` → `OutputSignedFile`，含 **Zip64 重试**（`:1167`）。摘要计算依赖块布局最终状态，乱序将导致摘要失真。权限签名经 `BuildPermSignSubBlock`/`ComputePermissionDigests`（`:828-957`），代码签名经 `BuildCodeSignSubBlock`→`CodeSigning::GetCodeSignBlock`（`:670`）。
- **fs-verity 计算需排除已写段**：`MerkleTreeBuilder` 多线程（`Uscript::ThreadPool`）构建 Merkle 树，`SetCsOffset` 让哈希计算跳过 codesign 区域，改动不得让签名段自身参与根哈希计算（自引用）。
- **验签只读不写**：`VerifyHap`/`VerifyElf`/`VerifyBin` 仅解析与验证，不得修改输入文件。
- **已知的拼写错误勿单独"修正"**：`constant.h:92` 命名空间注释误写 `UpdateEngine`（应为 `SignatureTools`）、`code_signing.cpp:192` `"DEBUF_LIB_ID"`（应为 `DEBUG_LIB_ID`）、多数包含保护 `SIGNATRUETOOLS_*_H`（应为 `SIGNATURETOOLS`）——单独修改会破坏一致性或引入下游包含顺序问题，如需修正须全量同步。
