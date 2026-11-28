/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.entity;

/**
 * Define const parameters
 *
 * @since 2021-12-13
 */
public class ParamConstants {
    /**
     * Signature algorithm name of SHA256withECDSA.
     */
    public static final String HAP_SIG_ALGORITHM_SHA256_ECDSA = "SHA256withECDSA";

    /**
     * Signature algorithm name of SHA384withECDSA.
     */
    public static final String HAP_SIG_ALGORITHM_SHA384_ECDSA = "SHA384withECDSA";

    /**
     * Signature algorithm name of SHA512withECDSA.
     */
    public static final String HAP_SIG_ALGORITHM_SHA512_ECDSA = "SHA512withECDSA";

    /**
     * Signature algorithm name of SHA256withRSA.
     */
    public static final String HAP_SIG_ALGORITHM_SHA256_RSA = "SHA256withRSA";

    /**
     * Signature algorithm name of SHA384withRSA.
     */
    public static final String HAP_SIG_ALGORITHM_SHA384_RSA = "SHA384withRSA";

    /**
     * Signature algorithm name of SHA256withRSA/PSS.
     */
    public static final String HAP_SIG_ALGORITHM_SHA256_RSA_PSS = "SHA256withRSA/PSS";

    /**
     * Signature algorithm name of SHA384withRSA/PSS.
     */
    public static final String HAP_SIG_ALGORITHM_SHA384_RSA_PSS = "SHA384withRSA/PSS";

    /**
     * Signature algorithm name of SHA512withRSA/PSS.
     */
    public static final String HAP_SIG_ALGORITHM_SHA512_RSA_PSS = "SHA512withRSA/PSS";

    /**
     * Signature algorithm name of SHA256withRSAANDMGF1.
     */
    public static final String HAP_SIG_ALGORITHM_SHA256_RSA_MGF1 = "SHA256withRSAANDMGF1";

    /**
     * Signature algorithm name of SHA384withRSAANDMGF1.
     */
    public static final String HAP_SIG_ALGORITHM_SHA384_RSA_MGF1 = "SHA384withRSAANDMGF1";

    /**
     * Signature algorithm name of SHA512withRSAANDMGF1.
     */
    public static final String HAP_SIG_ALGORITHM_SHA512_RSA_MGF1 = "SHA512withRSAANDMGF1";

    /**
     * Default value of zip-file align
     */
    public static final String ALIGNMENT = "4";

    /**
     * Signature mode
     */
    public static final String PARAM_SIGN_MODE = "mode";

    /**
     * Certificate revocation list
     */
    public static final String PARAM_BASIC_CRL = "crl";

    /**
     * Hap-file's property, stored developer info
     */
    public static final String PARAM_BASIC_PROPERTY = "property";

    /**
     * Hap-file's capability profile
     */
    public static final String PARAM_BASIC_PROFILE = "profileFile";

    /**
     * json type content of Hap-file's capability profile
     */
    public static final String PARAM_PROFILE_JSON_CONTENT = "profileContent";

    /**
     * Hap-file's proof-of-rotation
     */
    public static final String PARAM_BASIC_PROOF = "proof";

    /**
     * Alignment
     */
    public static final String PARAM_BASIC_ALIGNMENT = "a";

    /**
     * Private key used in signature
     */
    public static final String PARAM_BASIC_PRIVATE_KEY = "keyAlias";

    /**
     * Unsigned file
     */
    public static final String PARAM_BASIC_INPUT_FILE = "inFile";

    /**
     * Signed file
     */
    public static final String PARAM_BASIC_OUTPUT_FILE = "outFile";

    /**
     * Algorithm name of signature
     */
    public static final String PARAM_BASIC_SIGANTURE_ALG = "signAlg";

    /**
     * Flag indicates whether profile is signed
     */
    public static final String PARAM_BASIC_PROFILE_SIGNED = "profileSigned";

    /**
     * Flag indicates whether profile is signed
     */
    public static final String PROFILE_UNSIGNED = "0";

    /**
     * Flag indicates whether profile is signed
     */
    public static final String PROFILE_SIGNED = "1";

    /**
     * Module.json file path
     */
    public static final String PARAM_MODULE_FILE = "moduleFile";

    /**
     * Self sign mode flag
     */
    public static final String PARAM_SELF_SIGN = "selfSign";

    /**
     * Sign code parameter (used in some sign scenarios)
     */
    public static final String PARAM_SIGN_CODE = "signCode";

    /**
     * Self sign type value 1 - enable self sign
     */
    public static final String SELF_SIGN_TYPE_1 = "1";

    /**
     * Self sign type value 0 - disable self sign
     */
    public static final String SELF_SIGN_TYPE_0 = "0";

    /**
     * Skip code sign flag
     */
    public static final String PARAM_SKIP_CODE_SIGN = "skipCodeSign";

    /**
     * Skip code sign value true - skip code signing step
     */
    public static final String SKIP_CODE_SIGN_TRUE = "true";

    /**
     * Skip code sign value false - do not skip code signing step
     */
    public static final String SKIP_CODE_SIGN_FALSE = "false";

    /**
     * Permission version constant
     */
    public static final int PERMISSION_VERSION = 1;

    /**
     * Url of signature server
     */
    public static final String PARAM_REMOTE_SERVER = "signServer";

    /**
     * username used in remote sign mode
     */
    public static final String PARAM_REMOTE_USERNAME = "username";

    /**
     * password used in remote sign mode
     */
    public static final String PARAM_REMOTE_CODE = "password";

    /**
     * Local keystore path
     */
    public static final String PARAM_LOCAL_JKS_KEYSTORE = "keystoreFile";

    /**
     * The password of keystore
     */
    public static final String PARAM_LOCAL_JKS_KEYSTORE_CODE = "keystorePwd";

    /**
     * The key alias password
     */
    public static final String PARAM_LOCAL_JKS_KEYALIAS_CODE = "keyPwd";

    /**
     * The certificate file path
     */
    public static final String PARAM_LOCAL_PUBLIC_CERT = "appCertFile";
}