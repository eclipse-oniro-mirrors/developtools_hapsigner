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

package com.ohos.hapsigntool.hap.verify;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.ohos.elfio.Elfio;
import com.ohos.elfio.Section;
import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.error.ProfileException;
import com.ohos.hapsigntool.error.SignToolErrMsg;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.LogUtils;
import com.ohos.hapsigntool.utils.StringUtils;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Class of verify ELF.
 *
 * @since 2023/11/23
 */
public class VerifyElf {
    private static final LogUtils LOGGER = new LogUtils(VerifyElf.class);

    private static final int PAGE_SIZE = 4096;

    private static final int FLAG_SELF_SIGN = 1 << 4;

    private static final String PROFILE_SEC_NAME = ".profile";

    private static final String PERMISSION_SEC_NAME = ".permission";

    private static final String CODE_SIGN_SEC_NAME = ".codesign";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static String getProfileContent(byte[] profile) throws ProfileException {
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(profile);
            if (!VerifyUtils.verifyCmsSignedData(cmsSignedData)) {
                throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_INVALID.toString());
            }
            Object contentObj = cmsSignedData.getSignedContent().getContent();
            if (!(contentObj instanceof byte[])) {
                throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED.toString(
                    "Check profile failed, signed profile content is not byte array!"));
            }
            return new String((byte[]) contentObj, StandardCharsets.UTF_8);
        } catch (CMSException e) {
            return new String(profile, StandardCharsets.UTF_8);
        }
    }

    /**
     * Check whether parameters are valid
     *
     * @param options input parameters used to verify ELF.
     * @return true, if all parameters are valid.
     */
    public boolean checkParams(Options options) {
        if (!options.containsKey(ParamConstants.PARAM_BASIC_INPUT_FILE)) {
            LOGGER.error("Missing parameter: {}", ParamConstants.PARAM_BASIC_INPUT_FILE);
            return false;
        }
        return true;
    }

    /**
     * verify elf file.
     *
     * @param options input parameters used to verify elf.
     * @return true, if verify successfully.
     */
    public boolean verify(Options options) {
        VerifyResult verifyResult;
        try {
            if (!checkParams(options)) {
                LOGGER.error("Check params failed!");
                throw new IOException();
            }
            String filePath = options.getString(ParamConstants.PARAM_BASIC_INPUT_FILE);
            if (StringUtils.isEmpty(filePath)) {
                LOGGER.error("Not found verify file path!");
                throw new IOException();
            }
            File signedFile = new File(filePath);
            if (!checkSignFile(signedFile)) {
                LOGGER.error("Check input signature ELF false!");
                throw new IOException();
            }
            verifyResult = verifyElf(filePath);
            if (!verifyResult.isVerified()) {
                LOGGER.error("verify: {}", verifyResult.getMessage());
                throw new IOException();
            }
        } catch (IOException e) {
            LOGGER.error("Write certificate chain error", e);
            return false;
        }

        LOGGER.info("verify: {}", verifyResult.getMessage());
        return true;
    }

    private void writeCertificate(String destFile, List<X509Certificate> certificates) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(destFile))) {
            for (final X509Certificate cert : certificates) {
                writer.write(cert.getSubjectDN().toString() + System.lineSeparator());
                writer.writeObject(cert);
            }
            LOGGER.info("Write certificate chain success!");
        }
    }

    private void outputOptionalBlocks(String outputProfileFile, VerifyResult verifyResult) throws IOException {
        byte[] profile = verifyResult.getProfile();
        if (profile != null) {
            writeOptionalBytesToFile(profile, outputProfileFile);
        }
    }

    private void writeOptionalBytesToFile(byte[] data, String outputFile) throws IOException {
        if (outputFile == null || outputFile.isEmpty()) {
            return;
        }
        try (OutputStream out = Files.newOutputStream(Paths.get(outputFile))) {
            out.write(data);
            out.flush();
        }
    }

    private boolean checkSignFile(File signedFile) {
        try {
            FileUtils.isValidFile(signedFile);
        } catch (IOException e) {
            LOGGER.error("signedFile is invalid.", e);
            return false;
        }
        return true;
    }

    /**
     * Print permission section content
     *
     * @param elfio ELF file object
     */
    private void printPermissionContent(Elfio elfio) {
        Section sec = elfio.getSection(PERMISSION_SEC_NAME);
        if (sec == null) {
            LOGGER.info("permission is not found");
            return;
        }

        byte[] data = sec.getData();
        if (data == null || data.length == 0) {
            LOGGER.info("permission is empty");
            return;
        }

        String content = new String(data, StandardCharsets.UTF_8);
        // Try to format JSON using Gson
        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            JsonElement jsonElement = JsonParser.parseString(content);
            content = gson.toJson(jsonElement);
        } catch (JsonParseException e) {
            // If parsing fails, use original content
        }
        LOGGER.info("+++++++++++++++++++++++++++++++++permission+++++++++++++++++++++++++++++++++++++");
        LOGGER.info("{}", content);
    }

    /**
     * Print certificate information to console
     *
     * @param certHolder Certificate holder
     * @param certNum Certificate number in chain
     */
    private void printCertificate(X509CertificateHolder certHolder, int certNum) {
        try {
            LOGGER.info("+++++++++++++++++++++++++++++++certificate #{}+++++++++++++++++++++++++++++++++++", certNum);

            // Convert to Java X509Certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(certHolder.getEncoded()));

            // Print certificate information
            LOGGER.info("        Subject: {}", cert.getSubjectX500Principal());
            LOGGER.info("        Issuer: {}", cert.getIssuerX500Principal());
            LOGGER.info("        Serial Number: {}", cert.getSerialNumber());
            LOGGER.info("        Not Before: {}", cert.getNotBefore());
            LOGGER.info("        Not After: {}", cert.getNotAfter());
            LOGGER.info("        Signature Algorithm: {}", cert.getSigAlgName());
            LOGGER.info("        Version: {}", cert.getVersion());

            // Print public key info
            java.security.PublicKey publicKey = cert.getPublicKey();
            LOGGER.info("        Public Key Algorithm: {}", publicKey.getAlgorithm());
        } catch (CertificateException | IOException e) {
            LOGGER.error("Error printing certificate: {}", e.getMessage());
        }
    }

    /**
     * Verify elf file.
     *
     * @param binFile path of elf file.
     * @return VerifyResult containing verification result, certificates and profile.
     */
    public VerifyResult verifyElf(String binFile) {
        File bin = new File(binFile);

        // Check if file exists and is readable
        if (!bin.exists() || !bin.isFile()) {
            LOGGER.error("File does not exist or is not a file: {}", binFile);
            return new VerifyResult(false, VerifyResult.RET_FILE_NOT_FOUND_ERROR,
                "File does not exist or is not a file: " + binFile);
        }

        try {
            LOGGER.info("ELF verification started for file: {}", binFile);

            // Load ELF file using ELFIO
            Elfio elfio = new Elfio();
            if (!elfio.load(binFile)) {
                LOGGER.error("Failed to load ELF file: {}", binFile);
                return new VerifyResult(false, VerifyResult.RET_UNSUPPORTED_FORMAT_ERROR,
                    "Failed to load ELF file: " + binFile);
            }

            // Print permission section content
            printPermissionContent(elfio);

            // Parse code sign block and extract certificates/profile
            VerifyResult result = parseSignBlockAndExtract(elfio);
            if (!result.isVerified()) {
                LOGGER.error("Parse code sign block failed");
                return result;
            }

            return result;
        } catch (IOException e) {
            LOGGER.error("IO error while verifying ELF file: {}", e.getMessage(), e);
            return new VerifyResult(false, VerifyResult.RET_IO_ERROR,
                "IO error while verifying ELF file: " + e.getMessage());
        }
    }

    /**
     * Parse code sign block and extract certificates and profile
     *
     * @param elfio ELF file object
     * @return VerifyResult with extracted certificates and profile
     */
    private VerifyResult parseSignBlockAndExtract(Elfio elfio) {
        try {
            Section sec = elfio.getSection(CODE_SIGN_SEC_NAME);
            if (sec == null) {
                LOGGER.info("code signature is not found");
                return new VerifyResult(true, VerifyResult.RET_SUCCESS, "No signature found");
            }
            VerifyResult validationResult = validateCodeSignSection(sec);
            if (validationResult != null) {
                return validationResult;
            }
            ElfSignInfo signInfo = ElfSignInfo.fromByteArray(sec.getData());

            // Check self-sign flag
            if ((signInfo.getFlags() & FLAG_SELF_SIGN) == FLAG_SELF_SIGN) {
                LOGGER.info("code signature is self-sign");
                return new VerifyResult(true, VerifyResult.RET_SUCCESS, "Self-sign signature");
            }

            byte[] signature = signInfo.getSignature();
            if (signature == null || signature.length == 0) {
                LOGGER.error("signature data is empty");
                return new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR, "Signature data is empty");
            }
            List<X509Certificate> certificateList = parseCertificates(signature);
            byte[] profile = extractProfileFromSection(elfio);

            VerifyResult result = new VerifyResult(true, VerifyResult.RET_SUCCESS, "verify signature success");
            result.setCertificates(certificateList);
            result.setProfile(profile);

            return result;
        } catch (CMSException | CertificateException | IOException e) {
            LOGGER.error("Parse PKCS7 signature error: {}", e.getMessage());
            return new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR,
                "Failed to parse PKCS7 signature: " + e.getMessage());
        }
    }

    private VerifyResult validateCodeSignSection(Section sec) {
        if (sec.getOffset() % PAGE_SIZE != 0) {
            LOGGER.error("code signature section offset is not aligned");
            return new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR, "Code signature offset not aligned");
        }
        byte[] data = sec.getData();
        if (data == null || data.length == 0) {
            LOGGER.error("code signature section data is empty");
            return new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR, "Code signature data is empty");
        }
        long csBlockSize = sec.getSize();
        if (csBlockSize == 0 || csBlockSize % PAGE_SIZE != 0) {
            LOGGER.error("code signature section size is not aligned");
            return new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR, "Code signature size not aligned");
        }
        return null;
    }

    private List<X509Certificate> parseCertificates(byte[] signature)
        throws CMSException, CertificateException, IOException {
        CMSSignedData cmsSignedData = new CMSSignedData(signature);
        Collection<X509CertificateHolder> certHolderCollection = cmsSignedData.getCertificates().getMatches(null);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificateList = new ArrayList<>();

        int certNum = 0;
        for (X509CertificateHolder certHolder : certHolderCollection) {
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(
                new java.io.ByteArrayInputStream(certHolder.getEncoded()));
            certificateList.add(cert);
            printCertificate(certHolder, certNum++);
        }
        LOGGER.info("+++++++++++++++++++++++++++++++++signature++++++++++++++++++++++++++++++++++++");
        LOGGER.info("signature size: {} bytes", signature.length);
        LOGGER.info("certificate count: {}", certNum);
        return certificateList;
    }

    private byte[] extractProfileFromSection(Elfio elfio) {
        Section profileSec = elfio.getSection(PROFILE_SEC_NAME);
        if (profileSec == null) {
            return null;
        }
        byte[] profileData = profileSec.getData();
        if (profileData == null || profileData.length == 0) {
            return null;
        }
        LOGGER.info("Extracted profile from .profile section, size: {} bytes", profileData.length);
        return profileData;
    }
}
