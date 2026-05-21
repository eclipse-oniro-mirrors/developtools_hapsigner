/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

import com.ohos.hapsigntool.entity.ContentDigestAlgorithm;
import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.exception.VerifyCodeSignException;
import com.ohos.hapsigntool.codesigning.sign.VerifyCodeSignature;
import com.ohos.hapsigntool.entity.Pair;
import com.ohos.hapsigntool.entity.SignatureAlgorithm;
import com.ohos.hapsigntool.error.SignToolErrMsg;
import com.ohos.hapsigntool.hap.entity.PermissionDigestItem;
import com.ohos.hapsigntool.hap.entity.SigningBlock;
import com.ohos.hapsigntool.error.HapFormatException;
import com.ohos.hapsigntool.error.ProfileException;
import com.ohos.hapsigntool.error.SignatureNotFoundException;
import com.ohos.hapsigntool.hap.sign.SignHap;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.hap.utils.HapUtils;
import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.utils.LogUtils;
import com.ohos.hapsigntool.utils.StringUtils;
import com.ohos.hapsigntool.zip.ByteBufferZipDataInput;
import com.ohos.hapsigntool.zip.RandomAccessFileZipDataInput;
import com.ohos.hapsigntool.zip.UnsignedDecimalUtil;
import com.ohos.hapsigntool.zip.Zip;
import com.ohos.hapsigntool.zip.ZipDataInput;
import com.ohos.hapsigntool.zip.ZipFileInfo;
import com.ohos.hapsigntool.zip.ZipUtils;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.stream.Collectors;

/**
 * Class of verify hap.
 *
 * @since 2021/12/23
 */
public class VerifyHap {
    private static final LogUtils LOGGER = new LogUtils(VerifyHap.class);
    private static final int ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH = 32;
    private static final int ZIP_HEAD_OF_SIGNING_BLOCK_COUNT_OFFSET_REVERSE = 28;
    private static final int ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH = 12;
    private static final int PERMISSION_SIGN_BLOCK_MIN_SIZE = 20;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final boolean isPrintCert;

    public VerifyHap() {
        this(true);
    }

    public VerifyHap(boolean isPrintCert) {
        this.isPrintCert = isPrintCert;
    }

    private static String getProfileContent(byte[] profile) throws ProfileException {
        byte[] profileContentBytes = getProfileContentBytes(profile);
        return new String(profileContentBytes, StandardCharsets.UTF_8);
    }

    private static byte[] getProfileContentBytes(byte[] profile) throws ProfileException {
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(profile);
            if (!VerifyUtils.verifyCmsSignedData(cmsSignedData)) {
                throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_INVALID.toString());
            }
            Object contentObj = cmsSignedData.getSignedContent().getContent();
            if (!(contentObj instanceof byte[])) {
                throw new ProfileException(SignToolErrMsg.VERIFY_PROFILE_FAILED
                        .toString("Check profile failed, signed profile content is not byte array!"));
            }
            return (byte[]) contentObj;
        } catch (CMSException e) {
            return profile;
        }
    }

    /**
     * Check whether parameters are valid
     *
     * @param options input parameters used to verify hap.
     * @return true, if all parameters are valid.
     */
    public boolean checkParams(Options options) {
        if (!options.containsKey(ParamConstants.PARAM_VERIFY_CERTCHAIN_FILE)) {
            LOGGER.error("Missing parameter: {}", ParamConstants.PARAM_VERIFY_CERTCHAIN_FILE);
            return false;
        }
        if (!options.containsKey(ParamConstants.PARAM_VERIFY_PROFILE_FILE)) {
            LOGGER.error("Missing parameter: {}", ParamConstants.PARAM_VERIFY_PROFILE_FILE);
            return false;
        }
        if (!options.containsKey(ParamConstants.PARAM_VERIFY_PROOF_FILE)) {
            LOGGER.warn("Missing parameter: {}", ParamConstants.PARAM_VERIFY_PROOF_FILE);
        }
        return true;
    }

    /**
     * verify hap file.
     *
     * @param options input parameters used to verify hap.
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
                LOGGER.error("Check input signature hap false!");
                throw new IOException();
            }
            verifyResult = verifyHap(filePath);
            if (!verifyResult.isVerified()) {
                LOGGER.error("verify: {}", verifyResult.getMessage());
                throw new IOException();
            }
            String outputCertPath = options.getString(ParamConstants.PARAM_VERIFY_CERTCHAIN_FILE);
            if (verifyResult.getCertificates() != null) {
                writeCertificate(outputCertPath, verifyResult.getCertificates());
            }
        } catch (IOException e) {
            LOGGER.error("Write certificate chain error", e);
            return false;
        }

        String outputProfileFile = options.getString(ParamConstants.PARAM_VERIFY_PROFILE_FILE);
        String outputProofFile = options.getString(ParamConstants.PARAM_VERIFY_PROOF_FILE);
        String outputPropertyFile = options.getString(ParamConstants.PARAM_VERIFY_PROPERTY_FILE);
        try {
            outputOptionalBlocks(outputProfileFile, outputProofFile, outputPropertyFile, verifyResult);
        } catch (IOException e) {
            LOGGER.error("Output optional blocks error", e);
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

    private void outputOptionalBlocks(String outputProfileFile, String outputProofFile, String outputPropertyFile,
                                      VerifyResult verifyResult) throws IOException {
        List<SigningBlock> optionalBlocks = verifyResult.getOptionalBlocks();
        if (optionalBlocks != null && optionalBlocks.size() > 0) {
            for (SigningBlock optionalBlock : optionalBlocks) {
                int type = optionalBlock.getType();
                switch (type) {
                    case HapUtils.HAP_PROFILE_BLOCK_ID:
                        writeOptionalBytesToFile(optionalBlock.getValue(), outputProfileFile);
                        break;
                    case HapUtils.HAP_PROOF_OF_ROTATION_BLOCK_ID:
                        writeOptionalBytesToFile(optionalBlock.getValue(), outputProofFile);
                        break;
                    case HapUtils.HAP_PROPERTY_BLOCK_ID:
                        writeOptionalBytesToFile(optionalBlock.getValue(), outputPropertyFile);
                        break;
                    case HapUtils.HAP_SIGNATURE_SCHEME_V1_BLOCK_ID:
                    case HapUtils.ENTERPRISE_CODE_RE_SIGN_BLOCK_ID:
                    case HapUtils.ENTERPRISE_RE_SIGN_BLOCK_ID:
                        break;
                    default:
                        throw new IOException("Unsupported Block Id: 0x" + Long.toHexString(type));
                }
            }
        }
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
     * Verify hap file.
     *
     * @param hapFilePath path of hap file.
     * @return true, if verify successfully.
     */
    public VerifyResult verifyHap(String hapFilePath) {
        VerifyResult result;
        try (RandomAccessFile fle = new RandomAccessFile(hapFilePath, "r")) {
            ZipDataInput hapFile = new RandomAccessFileZipDataInput(fle);
            ZipFileInfo zipInfo = ZipUtils.findZipInfo(hapFile);
            long eocdOffset = zipInfo.getEocdOffset();
            if (ZipUtils.checkZip64EoCDLocatorIsPresent(hapFile, eocdOffset)) {
                String errorMsg = "ZIP64 format not supported!";
                LOGGER.error(errorMsg);
                return new VerifyResult(false, VerifyResult.RET_UNSUPPORTED_FORMAT_ERROR, errorMsg);
            }
            HapUtils.HapSignBlockInfo hapSigningBlockAndOffsetInFile = HapUtils.findHapSigningBlock(hapFile, zipInfo);
            ByteBuffer signingBlock = hapSigningBlockAndOffsetInFile.getContent();
            signingBlock.order(ByteOrder.LITTLE_ENDIAN);
            Pair<ByteBuffer, List<SigningBlock>> blockPair = getHapSignatureSchemeBlockAndOptionalBlocks(signingBlock);
            ByteBuffer signatureSchemeBlock = blockPair.getFirst();
            List<SigningBlock> optionalBlocks = blockPair.getSecond();
            Collections.reverse(optionalBlocks);
            if (!checkCodeSign(hapFilePath, optionalBlocks)) {
                return new VerifyResult(false, VerifyResult.RET_CODESIGN_DATA_ERROR, "code sign verify failed");
            }
            HapVerify verifyEngine = getHapVerify(hapFile, zipInfo, hapSigningBlockAndOffsetInFile,
                    signatureSchemeBlock, optionalBlocks);
            result = verifyEngine.verify();
            if (result.isVerified() && !verifyPermissionSign(hapFilePath, optionalBlocks, result)) {
                // verify permission sign
                return new VerifyResult(false, VerifyResult.RET_PERMISSION_SIGN_ERROR,
                        "permission sign verify failed");
            }
            result.setZipInfo(zipInfo);
            result.setHapSignBlockInfo(hapSigningBlockAndOffsetInFile);
            result.setSignBlockVersion(hapSigningBlockAndOffsetInFile.getVersion());
        } catch (IOException e) {
            LOGGER.error("Verify Hap has IO error!", e);
            result = new VerifyResult(false, VerifyResult.RET_IO_ERROR, e.getMessage());
        } catch (SignatureNotFoundException e) {
            LOGGER.error("Verify Hap failed, signature not found.", e);
            result = new VerifyResult(false, VerifyResult.RET_SIGNATURE_NOT_FOUND_ERROR, e.getMessage());
        } catch (HapFormatException e) {
            LOGGER.error("Verify Hap failed, unsupported format hap.", e);
            result = new VerifyResult(false, VerifyResult.RET_UNSUPPORTED_FORMAT_ERROR, e.getMessage());
        } catch (FsVerityDigestException e) {
            LOGGER.error("Verify Hap failed, fs-verity digest generate failed.", e);
            result = new VerifyResult(false, VerifyResult.RET_DIGEST_ERROR, e.getMessage());
        } catch (VerifyCodeSignException e) {
            LOGGER.error("Verify Hap failed, code sign block verify failed.", e);
            result = new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR, e.getMessage());
        } catch (CMSException e) {
            LOGGER.error("Verify Hap failed, code signature verify failed.", e);
            result = new VerifyResult(false, VerifyResult.RET_SIGNATURE_ERROR, e.getMessage());
        } catch (ProfileException e) {
            LOGGER.error("Verify Hap failed, parse app-identifier from profile failed, profile is invalid", e);
            return new VerifyResult(false, VerifyResult.RET_CODE_SIGN_BLOCK_ERROR, e.getMessage());
        }
        return result;
    }

    private HapVerify getHapVerify(ZipDataInput hapFile, ZipFileInfo zipInfo,
                                   HapUtils.HapSignBlockInfo hapSigningBlockAndOffsetInFile,
                                   ByteBuffer signatureSchemeBlock, List<SigningBlock> optionalBlocks) {
        long signingBlockOffset = hapSigningBlockAndOffsetInFile.getOffset();
        ZipDataInput beforeHapSigningBlock = hapFile.slice(0, signingBlockOffset);
        ZipDataInput centralDirectoryBlock = hapFile.slice(zipInfo.getCentralDirectoryOffset(),
                zipInfo.getCentralDirectorySize());
        ByteBuffer eocdBbyteBuffer = zipInfo.getEocd();
        ZipUtils.setCentralDirectoryOffset(eocdBbyteBuffer, signingBlockOffset);
        ZipDataInput eocdBlock = new ByteBufferZipDataInput(eocdBbyteBuffer);
        HapVerify verifyEngine = new HapVerify(beforeHapSigningBlock, signatureSchemeBlock,
                centralDirectoryBlock, eocdBlock, optionalBlocks);
        verifyEngine.setIsPrintCert(isPrintCert);
        return verifyEngine;
    }

    private boolean verifyPermissionSign(String hapFilePath, List<SigningBlock> optionalBlocks,
            VerifyResult verifyResult) throws IOException, ProfileException, HapFormatException {
        SigningBlock propertyBlock = findPropertyBlock(optionalBlocks);
        if (propertyBlock == null) {
            return true;
        }
        byte[] permissionSignBytes = findPermissionSignBytes(propertyBlock);
        if (permissionSignBytes == null) {
            return true;
        }
        ByteBuffer buffer = ByteBuffer.wrap(permissionSignBytes).order(ByteOrder.LITTLE_ENDIAN);
        PermissionVerifyInfo permissionVerifyInfo = parsePermissionSignBlock(buffer);
        if (permissionVerifyInfo.getMagic() != HapUtils.getHapPermissionSigningBlockMagic()) {
            LOGGER.error("verify permission sign failed, invalid magic number: {}",
                    Long.toString(permissionVerifyInfo.getMagic(), 16));
            return false;
        }
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(permissionVerifyInfo.getSignAlgId());
        if (signatureAlgorithm == null) {
            LOGGER.error("verify permission sign failed, unsupported sign alg id: {}",
                    permissionVerifyInfo.getSignAlgId());
            return false;
        }
        if (!verifyPermissionSignature(permissionVerifyInfo.getUnsignedContent(), permissionVerifyInfo.getSignature(),
                signatureAlgorithm, verifyResult)) {
            LOGGER.error("verify permission sign failed.");
            return false;
        }
        File inputHap = new File(hapFilePath);
        Pair<byte[], byte[]> moduleAndShareFileFromHap = HapUtils.findModuleAndShareFileFromHap(inputHap,
                new Zip(inputHap));
        byte[] modelContent = moduleAndShareFileFromHap.getFirst();
        if (modelContent == null) {
            LOGGER.error("verify permission sign failed, input file is not a stage hap.");
            return false;
        }
        if (modelContent.length == 0) {
            LOGGER.info("verify permission sign failed, empty module.json");
            return false;
        }
        SignHap.PermissionSignContent permissionSignContent = generatePermissionContent(moduleAndShareFileFromHap,
                optionalBlocks, propertyBlock);
        if (!verifyDigestContents(permissionSignContent, permissionVerifyInfo.getDigestContent(),
                permissionVerifyInfo.getDigestCount(), signatureAlgorithm)) {
            LOGGER.error("verify permission sign failed, verify digest items failed.");
            return false;
        }
        LOGGER.info("verify permission sign success.");
        return true;
    }

    private PermissionVerifyInfo parsePermissionSignBlock(ByteBuffer buffer) throws HapFormatException {
        ByteBuffer bufferCopy = buffer.slice();
        if (buffer.remaining() < PERMISSION_SIGN_BLOCK_MIN_SIZE) {
            throw new HapFormatException("parse permission failed, invalid permission signing block length: "
                    + buffer.remaining());
        }
        PermissionVerifyInfo permissionVerifyInfo = new PermissionVerifyInfo();
        long magic = buffer.getLong();
        permissionVerifyInfo.setMagic(magic);
        int signAlgId = buffer.getInt();
        permissionVerifyInfo.setSignAlgId(signAlgId);
        int digestLength = buffer.getInt();
        short digestCount = buffer.getShort();
        if (digestCount < 0) {
            throw new HapFormatException("parse permission sign block failed, invalid digest count: " + digestCount);
        }
        permissionVerifyInfo.setDigestCount(digestCount);
        if (digestLength < 0 || digestLength > buffer.remaining()) {
            throw new HapFormatException("parse permission sign block failed, invalid digest length: " + digestLength);
        }
        byte[] digests = new byte[digestLength];
        buffer.get(digests);
        permissionVerifyInfo.setDigestContent(digests);
        int position = buffer.position();
        byte[] signature = getPermissionSignature(buffer);
        permissionVerifyInfo.setSignature(signature);

        byte[] unsignData = new byte[position];
        bufferCopy.get(unsignData);
        permissionVerifyInfo.setUnsignedContent(unsignData);
        return permissionVerifyInfo;
    }

    private static byte[] getPermissionSignature(ByteBuffer buffer) throws HapFormatException {
        if (buffer.remaining() < Integer.BYTES) {
            throw new HapFormatException("parse permission signature failed, buffer remaining: "
                    + buffer.remaining() + " is too less");
        }
        int signatureLength = buffer.getInt();
        if (signatureLength < 0 || signatureLength > buffer.remaining()) {
            throw new HapFormatException("parse permission signature failed, buffer remaining: "
                    + buffer.remaining() + " less than signature length: " + signatureLength);
        }
        byte[] signature = new byte[signatureLength];
        buffer.get(signature);
        return signature;
    }

    private SigningBlock findPropertyBlock(List<SigningBlock> optionalBlocks) {
        SigningBlock propertyBlock = findBlockByType(optionalBlocks, HapUtils.ENTERPRISE_CODE_RE_SIGN_BLOCK_ID);
        if (propertyBlock == null) {
            propertyBlock = findBlockByType(optionalBlocks, HapUtils.HAP_PROPERTY_BLOCK_ID);
        }
        return propertyBlock;
    }

    private SignHap.PermissionSignContent generatePermissionContent(Pair<byte[], byte[]> moduleAndShareFileFromHap,
            List<SigningBlock> optionalBlocks, SigningBlock propertyBlock) throws IOException, ProfileException {
        SigningBlock profileBlock = findBlockByType(optionalBlocks, HapUtils.HAP_PROFILE_BLOCK_ID);
        byte[] profileBytes = Optional.ofNullable(profileBlock).map(SigningBlock::getValue).orElse(new byte[0]);
        profileBytes = getProfileContentBytes(profileBytes);
        byte[] codeSignBytes = findCodeSignBytes(propertyBlock);
        byte[] moduleContent = moduleAndShareFileFromHap.getFirst();
        byte[] shareFilesContent = moduleAndShareFileFromHap.getSecond();
        return new SignHap.PermissionSignContent(profileBytes, codeSignBytes, moduleContent, shareFilesContent);
    }

    private boolean verifyPermissionSignature(byte[] unsignData, byte[] signData,
            SignatureAlgorithm signatureAlgorithm, VerifyResult verifyResult) {
        List<SignerInformation> signerInfos = verifyResult.getSignerInfos();
        Store<X509CertificateHolder> certificateHolderStore = verifyResult.getCertificateHolderStore();
        for (SignerInformation signerInfo : signerInfos) {
            SignerId sid = signerInfo.getSID();
            X509CertificateSelector selector = new X509CertificateSelector(sid);
            Collection<X509CertificateHolder> matches = certificateHolderStore.getMatches(selector);
            if (matches.isEmpty()) {
                continue;
            }
            try {
                X509CertificateHolder next = matches.iterator().next();
                X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(next);
                Pair<String, ? extends AlgorithmParameterSpec> signatureAlgAndParams =
                        signatureAlgorithm.getSignatureAlgAndParams();
                Signature signature = Signature.getInstance(signatureAlgAndParams.getFirst());
                AlgorithmParameterSpec second = signatureAlgAndParams.getSecond();
                if (second != null) {
                    signature.setParameter(second);
                }
                signature.initVerify(certificate);
                signature.update(unsignData);
                boolean verify = signature.verify(signData);
                if (verify) {
                    return true;
                }
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException |
                     InvalidAlgorithmParameterException e) {
                LOGGER.error("verify permission signature failed, msg: {}", e.getMessage());
            }
        }
        return false;
    }

    private byte[] findCodeSignBytes(SigningBlock propertyBlock) throws IOException {
        byte[] value = propertyBlock.getValue();
        ByteBuffer buffer = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
        byte[] codeSignBytes = null;
        while (buffer.remaining() >= HapUtils.OPTIONAL_SUB_BLOCK_HEADER_SIZE) {
            int subBlockId = buffer.getInt();
            int length = buffer.getInt();
            buffer.getInt();
            if (buffer.remaining() < length) {
                throw new IOException("find permission sign block failed, block length "
                        + length + ", out of buffer remaining bytes " + buffer.remaining());
            }
            if (subBlockId == HapUtils.HAP_CODE_SIGN_BLOCK_ID) {
                codeSignBytes = new byte[length];
                buffer.get(codeSignBytes);
                break;
            } else {
                buffer.position(buffer.position() + length);
            }
        }
        return codeSignBytes;
    }

    private boolean verifyDigestContents(SignHap.PermissionSignContent permissionSignContent, byte[] digestContents,
            int digestCount, SignatureAlgorithm signatureAlgorithm) {
        ContentDigestAlgorithm digestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm();
        int digestOutputByteSize = digestAlgorithm.getDigestOutputByteSize();
        ByteBuffer byteBuffer = ByteBuffer.wrap(digestContents).order(ByteOrder.LITTLE_ENDIAN);
        Map<Integer, byte[]> exceptDigestMap = new HashMap<>();
        for (int i = 0; i < digestCount; i++) {
            int digestType = byteBuffer.getInt();
            byte[] digestBytes = new byte[digestOutputByteSize];
            byteBuffer.get(digestBytes);
            exceptDigestMap.put(digestType, digestBytes);
        }
        try {
            List<PermissionDigestItem> permissionDigestItems = HapUtils.calculatePermissionDigest(digestAlgorithm,
                    permissionSignContent);
            Map<Integer, byte[]> actualDigestMap = permissionDigestItems.stream()
                    .collect(Collectors.toMap(PermissionDigestItem::getType, PermissionDigestItem::getDigest));

            for (Map.Entry<Integer, byte[]> entry : actualDigestMap.entrySet()) {
                Integer realType = entry.getKey();
                byte[] actualDigest = entry.getValue();
                if (!exceptDigestMap.containsKey(realType)) {
                    LOGGER.error("verify permission digest failed, lost digest type: {}",
                            Integer.toString(realType, 16));
                    return false;
                }
                byte[] exceptDigest = exceptDigestMap.remove(realType);
                if (!Arrays.areEqual(actualDigest, exceptDigest)) {
                    LOGGER.error("verify permission digest failed, type: "
                            + Integer.toString(realType, 16) + ", excepted digest: {}, actual digest: {}",
                            Hex.toHexString(exceptDigest), Hex.toHexString(actualDigest));
                    return false;
                }
            }
            if (!exceptDigestMap.isEmpty()) {
                StringJoiner joiner = new StringJoiner(",");
                exceptDigestMap.keySet().forEach(type -> {
                    joiner.add(Integer.toString(type, 16));
                });
                LOGGER.error("verify permission digest failed, lost actual digest types: {}", joiner.toString());
                return false;
            }
        } catch (DigestException e) {
            LOGGER.error("calculate permission digest error, msg: {}", e.getMessage());
            return false;
        }
        return true;
    }

    private byte[] findPermissionSignBytes(SigningBlock propertyBlock) throws IOException {
        byte[] value = propertyBlock.getValue();
        ByteBuffer buffer = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
        byte[] permissionSignBytes = null;
        while (buffer.remaining() >= HapUtils.OPTIONAL_SUB_BLOCK_HEADER_SIZE) {
            int subBlockId = buffer.getInt();
            int length = buffer.getInt();
            buffer.getInt();
            if (buffer.remaining() < length) {
                throw new IOException("find permission sign block failed, block length "
                        + length + ", out of buffer remaining bytes " + buffer.remaining());
            }
            if (subBlockId == HapUtils.HAP_PERMISSION_SIGN_BLOCK_ID) {
                permissionSignBytes = new byte[length];
                buffer.get(permissionSignBytes);
                break;
            } else {
                buffer.position(buffer.position() + length);
            }
        }
        return permissionSignBytes;
    }

    private SigningBlock findBlockByType(List<SigningBlock> optionalBlocks, int type) {
        for (SigningBlock signingBlock : optionalBlocks) {
            if (signingBlock != null && signingBlock.getType() == type) {
                return signingBlock;
            }
        }
        return null;
    }

    /**
     * code sign check
     *
     * @param hapFilePath hap file path
     * @param optionalBlocks optional blocks
     * @return true or false
     * @throws FsVerityDigestException FsVerity digest on error
     * @throws IOException IO error
     * @throws VerifyCodeSignException verify code sign on error
     * @throws CMSException cms on error
     * @throws ProfileException profile of the hap error
     */
    private boolean checkCodeSign(String hapFilePath, List<SigningBlock> optionalBlocks)
            throws FsVerityDigestException, IOException, VerifyCodeSignException, CMSException, ProfileException {
        Map<Integer, byte[]> map = optionalBlocks.stream()
                .collect(Collectors.toMap(SigningBlock::getType, SigningBlock::getValue));
        byte[] propertyBlockArray = map.get(HapUtils.ENTERPRISE_CODE_RE_SIGN_BLOCK_ID);
        // check enterprise code re-sign
        if (propertyBlockArray != null && propertyBlockArray.length > 0) {
            LOGGER.info("Locate enterprise code re-sign data success.");
        } else {
            propertyBlockArray = map.get(HapUtils.HAP_PROPERTY_BLOCK_ID);
        }
        if (propertyBlockArray != null && propertyBlockArray.length > 0) {
            LOGGER.info("trying verify codesign block");
            String[] fileNameArray = hapFilePath.split("\\.");
            if (fileNameArray.length < ParamConstants.FILE_NAME_MIN_LENGTH) {
                LOGGER.error("ZIP64 format not supported");
                return false;
            }
            ByteBuffer byteBuffer = ByteBuffer.wrap(propertyBlockArray);
            ByteBuffer header = HapUtils.reverseSliceBuffer(byteBuffer, 0, ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH);
            long blockOffset = UnsignedDecimalUtil.getUnsignedInt(header);
            int blockLength = header.getInt();
            int blockType = header.getInt();
            if (blockType != HapUtils.HAP_CODE_SIGN_BLOCK_ID) {
                LOGGER.error("Verify Hap has no code sign data error!");
                return false;
            }
            File outputFile = new File(hapFilePath);
            byte[] profileArray = map.get(HapUtils.HAP_PROFILE_BLOCK_ID);
            String profileContent = getProfileContent(profileArray);
            String suffix = fileNameArray[fileNameArray.length - 1];
            boolean isCodeSign = VerifyCodeSignature.verifyHap(outputFile, blockOffset, blockLength,
                    suffix, profileContent);
            if (!isCodeSign) {
                LOGGER.error("Verify Hap has no code sign data error!");
                return false;
            }
            LOGGER.info("verify codesign success");
            return true;
        }
        LOGGER.info("can not find codesign block");
        return true;
    }

    private Pair<ByteBuffer, List<SigningBlock>> getHapSignatureSchemeBlockAndOptionalBlocks(ByteBuffer hapSigningBlock)
            throws SignatureNotFoundException {
        try {
            ByteBuffer header = HapUtils.reverseSliceBuffer(
                    hapSigningBlock,
                    hapSigningBlock.capacity() - ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH,
                    hapSigningBlock.capacity());
            ByteBuffer value = HapUtils.reverseSliceBuffer(hapSigningBlock, 0,
                    hapSigningBlock.capacity() - ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH);

            byte[] signatureValueBytes = new byte[value.capacity()];
            value.get(signatureValueBytes, 0, signatureValueBytes.length);
            signatureValueBytes = Arrays.reverse(signatureValueBytes);
            header.position(ZIP_HEAD_OF_SIGNING_BLOCK_COUNT_OFFSET_REVERSE); // position to the block count offset
            int blockCount = header.getInt();
            int current = value.capacity() - ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH * blockCount;
            value.position(current);

            int blockType = -1;
            int blockLength = -1;
            int blockOffset = -1;
            ByteBuffer hapSigningPkcs7Block = null;
            List<SigningBlock> optionalBlocks = new ArrayList<SigningBlock>();
            for (int i = 0; i < blockCount; i++) {
                blockOffset = value.getInt();
                blockLength = value.getInt();
                blockType = value.getInt();
                if (blockOffset + blockLength > signatureValueBytes.length) {
                    throw new SignatureNotFoundException("block end pos: " + (blockOffset + blockLength)
                            + " is larger than block len: " + signatureValueBytes.length);
                }
                if (HapUtils.getHapSignatureOptionalBlockIds().contains(blockType)) {
                    byte[] blockValue = Arrays.copyOfRange(signatureValueBytes, blockOffset, blockOffset + blockLength);
                    optionalBlocks.add(new SigningBlock(blockType, blockValue));
                }
                if (blockType == HapUtils.HAP_SIGNATURE_SCHEME_V1_BLOCK_ID) {
                    byte[] result = Arrays.copyOfRange(signatureValueBytes, blockOffset, blockOffset + blockLength);
                    hapSigningPkcs7Block = ByteBuffer.wrap(result);
                }
            }
            return Pair.create(hapSigningPkcs7Block, optionalBlocks);
        } finally {
            hapSigningBlock.clear();
        }
    }

    private static class PermissionVerifyInfo {
        private long magic;
        private int signAlgId;
        private short digestCount;
        private byte[] digestContent;
        private byte[] unsignedContent;
        private byte[] signature;

        public long getMagic() {
            return magic;
        }

        public void setMagic(long magic) {
            this.magic = magic;
        }

        public int getSignAlgId() {
            return signAlgId;
        }

        public void setSignAlgId(int signAlgId) {
            this.signAlgId = signAlgId;
        }

        public byte[] getDigestContent() {
            return digestContent;
        }

        public void setDigestContent(byte[] digestContent) {
            this.digestContent = digestContent;
        }

        public byte[] getUnsignedContent() {
            return unsignedContent;
        }

        public void setUnsignedContent(byte[] unsignedContent) {
            this.unsignedContent = unsignedContent;
        }

        public byte[] getSignature() {
            return signature;
        }

        public void setSignature(byte[] signature) {
            this.signature = signature;
        }

        public short getDigestCount() {
            return digestCount;
        }

        public void setDigestCount(short digestCount) {
            this.digestCount = digestCount;
        }
    }
}