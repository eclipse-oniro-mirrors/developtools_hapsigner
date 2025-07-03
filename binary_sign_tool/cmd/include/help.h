/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef HELP_H
#define HELP_H

#include <string>
 /* this file use to create help.txt content and
  * it is divided into 12 strings according
  * to the functional module
  */
namespace OHOS {
namespace SignatureTools {

const std::string HELP_TXT_HEADER = R"(
USAGE: <sign|verify>[options]
)";

const std::string SIGN_HELP_TXT = R"(
    sign[options]:
        -keyAlias : key alias, required fields;
        -keyPwd : key password, optional fields on localSign mode;
        -appCertFile : application signature certificate file, required fields on localSign mode, optional fields
    on remoteSign mode;
        -profileFile : signed Provision Profile file, p7b format, required fields;
        -profileSigned : indicates whether the profile file has a signature.The options are as follows
    : 1 : yes; 0:no; default value:1. optional fields;
        -inFile : input original elf file, required fields;
        -signAlg : signature algorithm, required fields, including SHA256withECDSA/SHA384withECDSA;
        -keystoreFile : keystore file, if signature mode is localSign, required fields on localSign mode,
    JKS or P12 format;
        -keystorePwd : keystore password, optional fields on localSign mode;
        -outFile : output the signed Provision Profile file, required fields;
    application package file format is hap;

        -moduleFile : module.json file.
        -selfSign : Whether the HAP file is self sign, The value 1 means enable self sign, and value 0 means disable self sign.
    The default value is 0. It is optional.

    EXAMPLE :
        sign -keyAlias "oh-app1-key-v1" -appCertFile "/home/app-release-cert.cer" -signCode "1"
-keystoreFile "/home/app-keypair.jks" -keystorePwd ****** -outFile "/home/app1-signed.hap
-profileFile "/home/signed-profile.p7b" -inFile "/home/app1-unsigned.hap" -signAlg SHA256withECDSA
)";

const std::string VERIFY_HELP_TXT = R"(
    verify[options]:
        -inFile : verify elf file, required fields;

    EXAMPLE:
        verify -inFile "/home/app1-signed.hap"
)";

const std::string HELP_END_TXT = R"(
COMMANDS :
    sign : elf file signature
    verify : elf file verification
)";
/* help.txt all content */
const std::string HELP_TXT = HELP_TXT_HEADER + SIGN_HELP_TXT + VERIFY_HELP_TXT + HELP_END_TXT;
}
}
#endif