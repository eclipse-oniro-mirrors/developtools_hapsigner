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

package com.ohos.hapsigntool.hap.sign;

import com.ohos.hapsigntool.entity.ContentDigestAlgorithm;
import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.entity.SignatureAlgorithm;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.entity.Pair;
import com.ohos.hapsigntool.hap.entity.PermissionDigestItem;
import com.ohos.hapsigntool.hap.entity.PermissionSignBlock;
import com.ohos.hapsigntool.hap.entity.SigningBlock;
import com.ohos.hapsigntool.error.SignatureException;
import com.ohos.hapsigntool.hap.utils.HapUtils;
import com.ohos.hapsigntool.zip.ZipDataInput;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * Hap Signature Scheme signer
 *
 * @since 2021/12/21
 */
public abstract class SignHap {
    private static final int BLOCK_COUNT = 4;
    private static final int BLOCK_MAGIC = 16;
    private static final int BLOCK_VERSION = 4;
    private static final int OPTIONAL_TYPE_SIZE = 4;
    private static final int OPTIONAL_LENGTH_SIZE = 4;
    private static final int OPTIONAL_OFFSET_SIZE = 4;

    private SignHap() {}

    private static byte[] getHapSigningBlock(
            Set<ContentDigestAlgorithm> contentDigestAlgorithms,
            List<SigningBlock> optionalBlocks,
            SignerConfig signerConfig,
            ZipDataInput[] hapData)
            throws SignatureException {
        /**
         * Compute digests of Hap contents
         * Sign the digests and wrap the signature and signer info into the Hap Signing Block
         */
        byte[] hapSignatureBytes = null;
        try {
            Map<ContentDigestAlgorithm, byte[]> contentDigests =
                    HapUtils.computeDigests(contentDigestAlgorithms, hapData, optionalBlocks);
            hapSignatureBytes = generateHapSigningBlock(signerConfig, contentDigests, optionalBlocks);
        } catch (DigestException | IOException e) {
            throw new SignatureException("Failed to compute digests of HAP", e);
        }
        return hapSignatureBytes;
    }

    private static byte[] generateHapSigningBlock(
            SignerConfig signerConfig,
            Map<ContentDigestAlgorithm, byte[]> contentDigests,
            List<SigningBlock> optionalBlocks)
            throws SignatureException {
        byte[] hapSignatureSchemeBlock = generateHapSignatureSchemeBlock(signerConfig, contentDigests);
        List<SigningBlock> signingBlocks = new ArrayList<>(optionalBlocks);
        signingBlocks.add(new SigningBlock(HapUtils.HAP_SIGNATURE_SCHEME_V1_BLOCK_ID, hapSignatureSchemeBlock));
        return generateHapSigningBlock(signingBlocks, signerConfig.getCompatibleVersion());
    }

    private static byte[] generateEnterpriseReHapSigningBlock(
            SignerConfig signerConfig,
            Map<ContentDigestAlgorithm, byte[]> contentDigests,
            List<SigningBlock> optionalBlocks)
            throws SignatureException {
        byte[] hapSignatureSchemeBlock = generateHapSignatureSchemeBlock(signerConfig, contentDigests);
        List<SigningBlock> signingBlocks = new ArrayList<>(optionalBlocks);
        signingBlocks.add(new SigningBlock(HapUtils.ENTERPRISE_RE_SIGN_BLOCK_ID, hapSignatureSchemeBlock));
        return generateHapSigningBlock(signingBlocks, signerConfig.getCompatibleVersion());
    }

    private static byte[] generateHapSigningBlock(List<SigningBlock> signingBlocks, int compatibleVersion) {
        // FORMAT:
        // Proof-of-Rotation pairs(optional):
        // uint32:type
        // uint32:length
        // uint32:offset
        // Property pairs(optional):
        // uint32:type
        // uint32:length
        // uint32:offset
        // Profile capability pairs(optional):
        // uint32:type
        // uint32:length
        // uint32:offset
        // length bytes : app signing pairs
        // uint32:type
        // uint32:length
        // uint32:offset
        // repeated ID-value pairs(reserved extensions):
        // length bytes : Proof-of-Rotation values
        // length bytes : property values
        // length bytes : profile capability values
        // length bytes : signature schema values
        // uint64: size
        // uint128: magic
        // uint32: version
        long blockSize = 0L;
        for (SigningBlock signingBlock : signingBlocks) {
            blockSize += signingBlock.getLength();
        }
        long resultSize =
                ((OPTIONAL_TYPE_SIZE + OPTIONAL_LENGTH_SIZE + OPTIONAL_OFFSET_SIZE) * signingBlocks.size())
                        + blockSize // optional pair
                        + BLOCK_COUNT // block count
                        + HapUtils.BLOCK_SIZE // size
                        + BLOCK_MAGIC // magic
                        + BLOCK_VERSION; // version
        if (resultSize > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("HapSigningBlock out of range : " + resultSize);
        }
        ByteBuffer result = ByteBuffer.allocate((int) resultSize);
        result.order(ByteOrder.LITTLE_ENDIAN);

        Map<Integer, Integer> typeAndOffsetMap = new HashMap<Integer, Integer>();
        int currentOffset = ((OPTIONAL_TYPE_SIZE + OPTIONAL_LENGTH_SIZE + OPTIONAL_OFFSET_SIZE) * signingBlocks.size());
        int currentOffsetInBlockValue = 0;
        int blockValueSizes = (int) blockSize;
        byte[] blockValues = new byte[blockValueSizes];

        for (SigningBlock optionalBlock : signingBlocks) {
            System.arraycopy(
                    optionalBlock.getValue(), 0, blockValues, currentOffsetInBlockValue, optionalBlock.getLength());
            typeAndOffsetMap.put(optionalBlock.getType(), currentOffset);
            currentOffset += optionalBlock.getLength();
            currentOffsetInBlockValue += optionalBlock.getLength();
        }
        extractedResult(signingBlocks, result, typeAndOffsetMap);
        result.put(blockValues);
        result.putInt(signingBlocks.size()); // Signing block count
        result.putLong(resultSize); // length of hap signing block
        result.put(HapUtils.getHapSigningBlockMagic(compatibleVersion)); // magic
        result.putInt(HapUtils.getHapSigningBlockVersion(compatibleVersion)); // version
        return result.array();
    }

    private static void extractedResult(List<SigningBlock> optionalBlocks, ByteBuffer result,
                                        Map<Integer, Integer> typeAndOffsetMap) {
        int offset;
        for (SigningBlock optionalBlock : optionalBlocks) {
            result.putInt(optionalBlock.getType()); // type
            result.putInt(optionalBlock.getLength()); // length
            offset = typeAndOffsetMap.get(optionalBlock.getType());
            result.putInt(offset); // offset
        }
    }

    private static byte[] generateHapSignatureSchemeBlock(
            SignerConfig signerConfig, Map<ContentDigestAlgorithm, byte[]> contentDigests) throws SignatureException {
        byte[] signerBlock = null;
        try {
            signerBlock = generateSignerBlock(signerConfig, contentDigests);
        } catch (SignatureException e) {
            throw new SignatureException("generate SignerBlock failed"
                    + "\nSolutions:"
                    + "\n> The keyAlias parameter is incorrect, please input a correct keyAlias parameter."
                    + "\n> The certificate is incorrect, please check if your certificate matches the key");
        }
        return signerBlock;
    }

    private static byte[] generateSignerBlock(
            SignerConfig signerConfig, Map<ContentDigestAlgorithm, byte[]> contentDigests) throws SignatureException {
        String mode = signerConfig.getOptions().getString(Options.MODE);
        if (!("remoteSign".equalsIgnoreCase(mode)) && signerConfig.getCertificates().isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }

        List<Pair<Integer, byte[]>> digests =
                new ArrayList<Pair<Integer, byte[]>>(signerConfig.getSignatureAlgorithms().size());
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.getSignatureAlgorithms()) {
            ContentDigestAlgorithm contentDigestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm();
            byte[] contentDigest = contentDigests.get(contentDigestAlgorithm);
            if (contentDigest == null) {
                throw new SignatureException(
                        contentDigestAlgorithm.getDigestAlgorithm()
                                + " content digest for "
                                + signatureAlgorithm.getSignatureAlgAndParams().getFirst()
                                + " not computed");
            }
            digests.add(Pair.create(signatureAlgorithm.getId(), contentDigest));
        }
        byte[] unsignedHapDigest = HapUtils.encodeListOfPairsToByteArray(digests);
        return Pkcs7Generator.BC.generateSignedData(unsignedHapDigest, signerConfig);
    }

    /**
     * Signs the provided Hap using Hap Signature Scheme and returns the
     * signed block as an array of ByteBuffer
     *
     * @param contents Hap content before ZIP CD
     * @param signerConfig signer config
     * @param optionalBlocks optional blocks
     * @return signed block
     * @throws SignatureException if an error occurs when sign hap file.
     */
    public static byte[] sign(ZipDataInput[] contents, SignerConfig signerConfig, List<SigningBlock> optionalBlocks)
            throws SignatureException {
        Set<ContentDigestAlgorithm> contentDigestAlgorithms = new HashSet<ContentDigestAlgorithm>();
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.getSignatureAlgorithms()) {
            contentDigestAlgorithms.add(signatureAlgorithm.getContentDigestAlgorithm());
        }
        return getHapSigningBlock(contentDigestAlgorithms, optionalBlocks, signerConfig, contents);
    }

    public static byte[] reSignEnterpriseApp(ZipDataInput[] contents, SignerConfig signerConfig,
            List<SigningBlock> optionalBlocks) throws SignatureException {
        Set<ContentDigestAlgorithm> contentDigestAlgorithms = new HashSet<ContentDigestAlgorithm>();
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.getSignatureAlgorithms()) {
            contentDigestAlgorithms.add(signatureAlgorithm.getContentDigestAlgorithm());
        }
        return getEnterpriseReHapSigningBlock(contentDigestAlgorithms, optionalBlocks, signerConfig, contents);
    }

    private static byte[] getEnterpriseReHapSigningBlock(
            Set<ContentDigestAlgorithm> contentDigestAlgorithms,
            List<SigningBlock> optionalBlocks,
            SignerConfig signerConfig,
            ZipDataInput[] hapData)
            throws SignatureException {
        /**
         * Compute digests of Hap contents
         * Sign the digests and wrap the signature and signer info into the Hap Signing Block
         */
        byte[] hapSignatureBytes = null;
        try {
            Map<ContentDigestAlgorithm, byte[]> contentDigests =
                    HapUtils.computeDigests(contentDigestAlgorithms, hapData, optionalBlocks);
            hapSignatureBytes = generateEnterpriseReHapSigningBlock(signerConfig, contentDigests, optionalBlocks);
        } catch (DigestException | IOException e) {
            throw new SignatureException("Failed to compute digests of HAP", e);
        }
        return hapSignatureBytes;
    }

    /**
     * Generate permission signing block.
     *
     * @param signerConfig signer config
     * @param permissionSignContent permission contents
     * @return permission signing block
     * @throws SignatureException if an error occurs when sign hap permission contents.
     */
    public static byte[] generatePermissionSigningBlock(SignerConfig signerConfig,
            PermissionSignContent permissionSignContent) throws SignatureException {
        try {
            SignatureAlgorithm signatureAlgorithm = signerConfig.getSignatureAlgorithms().get(0);
            ContentDigestAlgorithm digestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm();
            List<PermissionDigestItem> digestList = HapUtils.calculatePermissionDigest(digestAlgorithm,
                    permissionSignContent);
            byte[] permissionDigest = HapUtils.transferPermissionDigestToBytes(digestList);
            String signAlg = signatureAlgorithm.getSignatureAlgAndParams().getFirst();
            byte[] unsignData = new PermissionSignBlock(signatureAlgorithm.getId(), permissionDigest, digestList.size(),
                    HapUtils.getHapPermissionSigningBlockMagic()).toByteArray();
            byte[] signature = signerConfig.getSigner().getSignature(unsignData, signAlg,
                    signatureAlgorithm.getSignatureAlgAndParams().getSecond());
            int capacity = unsignData.length + signature.length + OPTIONAL_LENGTH_SIZE;
            ByteBuffer byteBuffer = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
            byteBuffer.put(unsignData);
            byteBuffer.putInt(signature.length);
            byteBuffer.put(signature);
            if (byteBuffer.hasArray()) {
                return byteBuffer.array();
            }
            byteBuffer.flip();
            byte[] result = new byte[byteBuffer.remaining()];
            byteBuffer.get(result);
            return result;
        } catch (DigestException | IOException e) {
            throw new SignatureException("Failed to compute permission content digests", e);
        }
    }

    /**
     * Hap permission sign content
     */
    public static class PermissionSignContent {
        private final byte[] profileContent;
        private final byte[] codeSignContent;
        private final byte[] moduleJsonContent;
        private final byte[] shareFilesContent;

        public PermissionSignContent(byte[] profileContent, byte[] codeSignContent, byte[] moduleJsonContent,
                byte[] shareFilesContent) {
            this.profileContent = profileContent;
            this.codeSignContent = codeSignContent;
            this.moduleJsonContent = moduleJsonContent;
            this.shareFilesContent = shareFilesContent;
        }

        public byte[] getProfileContent() {
            return profileContent;
        }

        public byte[] getCodeSignContent() {
            return codeSignContent;
        }

        public byte[] getModuleJsonContent() {
            return moduleJsonContent;
        }

        public byte[] getShareFilesContent() {
            return shareFilesContent;
        }
    }
}
