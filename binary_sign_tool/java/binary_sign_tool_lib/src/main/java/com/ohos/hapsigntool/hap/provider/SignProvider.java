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

package com.ohos.hapsigntool.hap.provider;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.entity.SignatureAlgorithm;
import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.error.InvalidParamsException;
import com.ohos.hapsigntool.error.ProfileException;
import com.ohos.hapsigntool.error.SignToolErrMsg;
import com.ohos.hapsigntool.error.VerifyCertificateChainException;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.hap.sign.SignElf;
import com.ohos.hapsigntool.hap.verify.VerifyUtils;
import com.ohos.hapsigntool.utils.CertificateUtils;
import com.ohos.hapsigntool.utils.DigestUtils;
import com.ohos.hapsigntool.utils.EscapeCharacter;
import com.ohos.hapsigntool.utils.LogUtils;
import com.ohos.hapsigntool.utils.ParamProcessUtil;
import com.ohos.hapsigntool.utils.StringUtils;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Sign provider super class
 *
 * @since 2021-12-14
 */
public abstract class SignProvider {
    private static final LogUtils LOGGER = new LogUtils(SignProvider.class);
    private static final List<String> VALID_SIGN_ALG_NAME = new ArrayList<String>();
    private static final List<String> PARAMETERS_NEED_ESCAPE = new ArrayList<String>();
    private static final long TIMESTAMP = 1230768000000L;
    private static final int COMPRESSION_MODE = 9;

    static {
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA256_ECDSA);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA384_ECDSA);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA512_ECDSA);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA256_RSA_PSS);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA384_RSA_PSS);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA512_RSA_PSS);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA256_RSA_MGF1);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA384_RSA_MGF1);
        VALID_SIGN_ALG_NAME.add(ParamConstants.HAP_SIG_ALGORITHM_SHA512_RSA_MGF1);
        Security.addProvider(new BouncyCastleProvider());
    }

    static {
        PARAMETERS_NEED_ESCAPE.add(ParamConstants.PARAM_REMOTE_CODE);
        PARAMETERS_NEED_ESCAPE.add(ParamConstants.PARAM_LOCAL_JKS_KEYSTORE_CODE);
        PARAMETERS_NEED_ESCAPE.add(ParamConstants.PARAM_LOCAL_JKS_KEYALIAS_CODE);
    }

    /**
     * parameters only used in signing
     */
    protected Map<String, String> signParams = new HashMap<String, String>();

    private String profileContent;

    /**
     * check if the input path is a file
     *
     * @param filePath input file path
     * @return true, if path is a file and can be read
     */
    private boolean checkFile(String filePath) {
        if (!(checkStringIsNotNullAndEmity(filePath))) {
            LOGGER.error("fileName is null");
            return false;
        }
        File file = new File(filePath);
        if (!file.canRead() || !file.isFile()) {
            LOGGER.error(filePath + " not exist or can not read!");
            return false;
        }
        return true;
    }

    private boolean checkStringIsNotNullAndEmity(String str) {
        return !(str == null || "".equals(str));
    }

    /**
     * Get certificate chain used to sign.
     *
     * @return list of x509 certificates.
     */
    private List<X509Certificate> getPublicCerts() {
        String publicCertsFile = signParams.get(ParamConstants.PARAM_LOCAL_PUBLIC_CERT);
        if (StringUtils.isEmpty(publicCertsFile)) {
            return Collections.emptyList();
        }
        return getCertificateChainFromFile(publicCertsFile);
    }

    /**
     * get certificate revocation list used to sign
     *
     * @return certificate revocation list
     */
    public Optional<X509CRL> getCrl() {
        return Optional.empty();
    }

    /**
     * Create SignerConfig by certificate chain and certificate revocation list.
     *
     * @param certificates certificate chain
     * @param crl certificate revocation list
     * @param options options
     * @return Object of SignerConfig
     */
    public SignerConfig createSignerConfigs(List<X509Certificate> certificates,
                                            Optional<X509CRL> crl, Options options) {
        SignerConfig signerConfig = new SignerConfig();
        signerConfig.setParameters(this.signParams);
        signerConfig.setCertificates(certificates);
        signerConfig.setOptions(options);

        List<SignatureAlgorithm> signatureAlgorithms = new ArrayList<SignatureAlgorithm>();
        signatureAlgorithms.add(
                ParamProcessUtil.getSignatureAlgorithm(this.signParams.get(ParamConstants.PARAM_BASIC_SIGANTURE_ALG)));
        signerConfig.setSignatureAlgorithms(signatureAlgorithms);

        if (!crl.equals(Optional.empty())) {
            signerConfig.setX509CRLs(Collections.singletonList(crl.get()));
        }
        return signerConfig;
    }

    /**
     * sign elf file
     *
     * @param options parameters used to sign elf file
     * @return true, if sign successfully.
     */
    public boolean signElf(Options options) {
        List<X509Certificate> publicCert = null;
        SignerConfig signerConfig = null;

        try {
            checkParams(options);
            checkSignatureAlg();
        } catch (InvalidParamsException e) {
            LOGGER.error("Sign elf error: {}", e.getMessage());
            return false;
        }

        try {
            publicCert = getX509Certificates(options);

            // Get x509 CRL
            Optional<X509CRL> crl = getCrl();

            // Create signer configs, which contains public cert and crl info.
            signerConfig = createSignerConfigs(publicCert, crl, options);
        } catch (InvalidParamsException | ProfileException e) {
            LOGGER.error("create signer configs failed.", e);
            return false;
        }

        if (profileContent != null) {
            signParams.put(ParamConstants.PARAM_PROFILE_JSON_CONTENT, profileContent);
        }
        /* 6. make signed file into output file. */
        if (!new SignElf().sign(signerConfig, signParams)) {
            LOGGER.error("Sign elf internal failed.");
            return false;
        }
        LOGGER.info("Sign success");
        return true;
    }

    /**
     * sign hap file
     * NOTE: ZIP format is no longer supported. This method will always fail.
     *
     * @param options parameters used to sign hap file
     * @return true, if sign successfully
     */
    public boolean sign(Options options) {
        LOGGER.error("ZIP format is no longer supported. Please use ELF or BIN format instead.");
        return false;
    }

    /**
     * Load certificate chain from input parameters
     *
     * @param options parameters used to sign hap file
     * @return list of type x509certificate
     * @throws InvalidParamsException Exception occurs when the required parameters are invalid.
     * @throws ProfileException Exception occurs when profile is invalid.
     */
    private List<X509Certificate> getX509Certificates(Options options) throws InvalidParamsException, ProfileException {
        List<X509Certificate> publicCerts;
        // 1. check the parameters
        checkParams(options);
        // 2. get x509 verify certificate
        publicCerts = getPublicCerts();
        // 3. load optionalBlocks
        if (StringUtils.isEmpty(options.getString(ParamConstants.PARAM_BASIC_PROFILE))) {
            return publicCerts;
        }
        return publicCerts;
    }

    /**
     * check signature algorithm
     *
     * @throws InvalidParamsException Exception occurs when the inputted sign algorithm is invalid.
     */
    private void checkSignatureAlg() throws InvalidParamsException {
        String signAlg = signParams.get(ParamConstants.PARAM_BASIC_SIGANTURE_ALG).trim();
        for (String validAlg : VALID_SIGN_ALG_NAME) {
            if (validAlg.equalsIgnoreCase(signAlg)) {
                return;
            }
        }
        LOGGER.error("Unsupported signature algorithm :" + signAlg);
        throw new InvalidParamsException(SignToolErrMsg.PARAM_CHECK_FAILED
                .toString(ParamConstants.PARAM_BASIC_SIGANTURE_ALG, "Invalid parameter: Sign Alg"));
    }

    /**
     * check alignment
     */
    protected void checkSignAlignment() {
        if (!signParams.containsKey(ParamConstants.PARAM_BASIC_ALIGNMENT)) {
            signParams.put(ParamConstants.PARAM_BASIC_ALIGNMENT, ParamConstants.ALIGNMENT);
        }
    }

    /**
     * Get CN value of developer certificate from profile.
     *
     * @param buildInfoObject json obect of buildInfo in profile.
     * @return Object of development-certificate.
     */
    private X509Certificate getDevelopmentCertificate(JsonObject buildInfoObject) {
        final String developmentCertElememt = "development-certificate";
        String developmentCertificate = buildInfoObject.get(developmentCertElememt).getAsString();
        return DigestUtils.decodeBase64ToX509Certifate(developmentCertificate);
    }

    /**
     * Get CN value of release certificate from profile.
     *
     * @param buildInfoObject json obect of buildInfo in profile.
     * @return Object of distribution-certificate.
     */
    private X509Certificate getReleaseCertificate(JsonObject buildInfoObject) {
        final String distributeCertElememt = "distribution-certificate";
        String distributeCertificate = buildInfoObject.get(distributeCertElememt).getAsString();
        return DigestUtils.decodeBase64ToX509Certifate(distributeCertificate);
    }

    private String getCertificateCN(X509Certificate cert) {
        if (cert == null) {
            return "";
        }
        String nameStr = cert.getSubjectX500Principal().getName();
        X500Name name = new X500Name(nameStr);
        RDN[] commonName = name.getRDNs(BCStyle.CN);
        if (commonName.length <= 0) {
            CustomException.throwException(ERROR.CERTIFICATE_ERROR, SignToolErrMsg.CERTIFICATE_ERROR
                    .toString("subject without common name"));
        }
        return commonName[0].getFirst().getValue().toString();
    }

    /**
     * Check profile is valid. A valid profile must include type and
     * certificate which has a non-empty value of DN.
     *
     * @param inputCerts certificates inputted by user.
     * @throws ProfileException Exception occurs when profile is invalid.
     */
    private void checkProfileValid(List<X509Certificate> inputCerts) throws ProfileException {
        try {
            byte[] profile = new byte[0];
            boolean isProfileWithoutSign = ParamConstants.PROFILE_UNSIGNED.equals(
                    signParams.get(ParamConstants.PARAM_BASIC_PROFILE_SIGNED));
            if (!isProfileWithoutSign) {
                CMSSignedData cmsSignedData = new CMSSignedData(profile);
                boolean isVerify = VerifyUtils.verifyCmsSignedData(cmsSignedData);
                if (!isVerify) {
                    throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_INVALID.toString());
                }
                Object contentObj = cmsSignedData.getSignedContent().getContent();
                if (!(contentObj instanceof byte[])) {
                    throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED
                            .toString("Check profile failed, signed profile content is not byte array!"));
                }
                profileContent = new String((byte[]) contentObj, StandardCharsets.UTF_8);
            } else {
                profileContent = new String(profile, StandardCharsets.UTF_8);
            }
            JsonElement parser = JsonParser.parseString(profileContent);
            JsonObject profileJson = parser.getAsJsonObject();
            checkProfileInfo(profileJson, inputCerts);
        } catch (CMSException e) {
            throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_INVALID.toString());
        } catch (JsonParseException e) {
            throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED
                    .toString("Invalid parameter: profile content is not a JSON.", e));
        }
    }

    private void checkProfileInfo(JsonObject profileJson, List<X509Certificate> inputCerts) throws ProfileException {
        String profileTypeKey = "type";
        String profileType = profileJson.get(profileTypeKey).getAsString();
        if (profileType == null || profileType.length() == 0) {
            throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED.toString("Get profile type error!"));
        }
        String buildInfoMember = "bundle-info";
        JsonObject buildInfoObject = profileJson.getAsJsonObject(buildInfoMember);
        X509Certificate certInProfile;
        if (profileType.equalsIgnoreCase("release")) {
            certInProfile = getReleaseCertificate(buildInfoObject);
        } else if (profileType.equalsIgnoreCase("debug")) {
            certInProfile = getDevelopmentCertificate(buildInfoObject);
        } else {
            throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED.toString("Unsupported profile type!"));
        }
        if (!inputCerts.isEmpty() && !checkInputCertMatchWithProfile(inputCerts.get(0), certInProfile)) {
            throw new ProfileException(SignToolErrMsg.PROFILE_CERT_MATCH_FAILED.toString());
        }
        String cn = getCertificateCN(certInProfile);
        LOGGER.info("certificate in profile: {}", cn);
        if (cn.isEmpty()) {
            throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED
                    .toString("Common name of certificate is empty!"));
        }
    }

    /**
     * check whether certificate inputted by user is matched with the certificate in profile.
     *
     * @param inputCert certificates inputted by user.
     * @param certInProfile the certificate in profile.
     * @return true, if it is match.
     */
    protected boolean checkInputCertMatchWithProfile(X509Certificate inputCert, X509Certificate certInProfile) {
        return true;
    }

    /**
     * Check input parameters is valid. And put valid parameters into signParams.
     *
     * @param options parameters inputted by user.
     * @throws InvalidParamsException Exception occurs when the required parameters are invalid.
     */
    public void checkParams(Options options) throws InvalidParamsException {
        String[] paramFileds = {
                ParamConstants.PARAM_BASIC_ALIGNMENT,
                ParamConstants.PARAM_BASIC_SIGANTURE_ALG,
                ParamConstants.PARAM_BASIC_INPUT_FILE,
                ParamConstants.PARAM_BASIC_OUTPUT_FILE,
                ParamConstants.PARAM_BASIC_PRIVATE_KEY,
                ParamConstants.PARAM_BASIC_PROFILE,
                ParamConstants.PARAM_BASIC_PROOF,
                ParamConstants.PARAM_BASIC_PROPERTY,
                ParamConstants.PARAM_REMOTE_SERVER,
                ParamConstants.PARAM_BASIC_PROFILE_SIGNED,
                ParamConstants.PARAM_LOCAL_PUBLIC_CERT,
                ParamConstants.PARAM_SIGN_CODE,
                ParamConstants.PARAM_MODULE_FILE,
                ParamConstants.PARAM_SELF_SIGN,
                ParamConstants.PARAM_SKIP_CODE_SIGN
        };
        Set<String> paramSet = ParamProcessUtil.initParamField(paramFileds);

        for (String paramKey : options.keySet()) {
            if (paramSet.contains(paramKey)) {
                signParams.put(paramKey, getParamValue(paramKey, options.getString(paramKey)));
            }
        }
        if (!signParams.containsKey(ParamConstants.PARAM_BASIC_PROFILE_SIGNED)) {
            signParams.put(ParamConstants.PARAM_BASIC_PROFILE_SIGNED, "1");
        }
        if (StringUtils.isEmpty(signParams.get(ParamConstants.PARAM_BASIC_PROFILE_SIGNED))) {
            signParams.put(ParamConstants.PARAM_BASIC_PROFILE_SIGNED, "1");
        }
        if (!signParams.containsKey(ParamConstants.PARAM_SELF_SIGN)) {
            signParams.put(ParamConstants.PARAM_SELF_SIGN, "0");
        }
        if (StringUtils.isEmpty(signParams.get(ParamConstants.PARAM_SELF_SIGN))) {
            signParams.put(ParamConstants.PARAM_SELF_SIGN, "0");
        }
        if (!signParams.containsKey(ParamConstants.PARAM_SKIP_CODE_SIGN)) {
            signParams.put(ParamConstants.PARAM_SKIP_CODE_SIGN, ParamConstants.SKIP_CODE_SIGN_FALSE);
        }
        if (StringUtils.isEmpty(signParams.get(ParamConstants.PARAM_SKIP_CODE_SIGN))) {
            signParams.put(ParamConstants.PARAM_SKIP_CODE_SIGN, ParamConstants.SKIP_CODE_SIGN_FALSE);
        }
        checkSignAlignment();
    }

    /**
     * Get parameters from inputted strings. This function unescape some escaped parameters and return it.
     *
     * @param paramName the name of parameter
     * @param paramValue the value of parameter
     * @return parameter value in the correct form.
     */
    protected String getParamValue(String paramName, String paramValue) {
        for (String name : PARAMETERS_NEED_ESCAPE) {
            if (name.equals(paramName)) {
                return EscapeCharacter.unescape(paramValue);
            }
        }
        return paramValue;
    }

    private List<X509Certificate> getCertificateChainFromFile(String certChianFile) {
        try {
            return CertificateUtils.getCertListFromFile(certChianFile);
        } catch (CertificateException e) {
            LOGGER.error("File content is not certificates! " + e.getMessage());
        } catch (IOException e) {
            LOGGER.error("Certificate file exception: " + e.getMessage());
        } catch (VerifyCertificateChainException e) {
            LOGGER.error(e.getMessage());
        }
        return Collections.emptyList();
    }
}
