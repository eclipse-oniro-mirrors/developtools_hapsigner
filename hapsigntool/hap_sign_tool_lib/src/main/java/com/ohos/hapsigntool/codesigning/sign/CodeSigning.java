/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.codesigning.sign;

import com.ohos.hapsigntool.codesigning.datastructure.CodeSignBlock;
import com.ohos.hapsigntool.codesigning.datastructure.ElfSignBlock;
import com.ohos.hapsigntool.codesigning.datastructure.Extension;
import com.ohos.hapsigntool.codesigning.datastructure.FsVerityInfoSegment;
import com.ohos.hapsigntool.codesigning.datastructure.MerkleTreeExtension;
import com.ohos.hapsigntool.codesigning.datastructure.PageInfoExtension;
import com.ohos.hapsigntool.codesigning.datastructure.SignInfo;
import com.ohos.hapsigntool.codesigning.exception.CodeSignException;
import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.fsverity.FsVerityDescriptor;
import com.ohos.hapsigntool.codesigning.fsverity.FsVerityDescriptorWithSign;
import com.ohos.hapsigntool.codesigning.fsverity.FsVerityGenerator;
import com.ohos.hapsigntool.codesigning.utils.HapUtils;
import com.ohos.hapsigntool.entity.Pair;
import com.ohos.hapsigntool.error.HapFormatException;
import com.ohos.hapsigntool.error.ProfileException;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.signer.LocalSigner;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.StringUtils;
import com.ohos.hapsigntool.zip.EntryType;
import com.ohos.hapsigntool.zip.Zip;
import com.ohos.hapsigntool.zip.ZipEntry;
import com.ohos.hapsigntool.zip.ZipEntryHeader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.zip.ZipInputStream;

/**
 * core functions of code signing
 *
 * @since 2023/06/05
 */
public class CodeSigning {
    /**
     * Only hap and hsp, hqf bundle supports code signing
     */
    public static final String[] SUPPORT_FILE_FORM = {"hap", "hsp", "hqf"};

    /**
     * Only elf file supports bin code signing
     */
    public static final String SUPPORT_BIN_FILE_FORM = "elf";

    /**
     * Defined entry name of hap file
     */
    public static final String HAP_SIGNATURE_ENTRY_NAME = "Hap";

    private static final Logger LOGGER = LogManager.getLogger(CodeSigning.class);

    private final SignerConfig signConfig;

    private CodeSignBlock codeSignBlock;

    private PageInfoExtension pageInfoExtension;

    /**
     * provide code sign functions to sign a hap
     *
     * @param signConfig configuration of sign
     */
    public CodeSigning(SignerConfig signConfig) {
        this.signConfig = signConfig;
    }

    /**
     * Sign the given elf file, and pack all signature into output file
     *
     * @param input  file to sign
     * @param offset position of codesign block based on start of the file
     * @param inForm file's format
     * @param profileContent profile of the elf
     * @return byte array of code sign block
     * @throws CodeSignException        code signing exception
     * @throws IOException              io error
     * @throws FsVerityDigestException  computing FsVerity digest error
     * @throws ProfileException         profile of elf is invalid
     */
    public byte[] getElfCodeSignBlock(File input, long offset, String inForm, String profileContent)
        throws CodeSignException, FsVerityDigestException, IOException, ProfileException {
        LOGGER.info("Start to sign code.");
        if (!SUPPORT_BIN_FILE_FORM.equalsIgnoreCase(inForm)) {
            throw new CodeSignException("file's format is unsupported");
        }
        long fileSize = input.length();
        int paddingSize = ElfSignBlock.computeMerkleTreePaddingLength(offset);
        long fsvTreeOffset = offset + Integer.BYTES * 2 + paddingSize;
        try (FileInputStream inputStream = new FileInputStream(input)) {
            FsVerityGenerator fsVerityGenerator = new FsVerityGenerator();
            fsVerityGenerator.generateFsVerityDigest(inputStream, fileSize, fsvTreeOffset);
            byte[] fsVerityDigest = fsVerityGenerator.getFsVerityDigest();
            // ownerID should be DEBUG_LIB_ID while signing ELF
            String ownerID = (profileContent == null)
                ? HapUtils.HAP_DEBUG_OWNER_ID
                : HapUtils.getAppIdentifier(profileContent);
            byte[] signature = generateSignature(fsVerityDigest, ownerID);
            // add fs-verify info
            FsVerityDescriptor.Builder fsdbuilder = new FsVerityDescriptor.Builder().setFileSize(fileSize)
                .setHashAlgorithm(FsVerityGenerator.getFsVerityHashAlgorithm())
                .setLog2BlockSize(FsVerityGenerator.getLog2BlockSize())
                .setSaltSize((byte) fsVerityGenerator.getSaltSize())
                .setSignSize(signature.length)
                .setFileSize(fileSize)
                .setSalt(fsVerityGenerator.getSalt())
                .setRawRootHash(fsVerityGenerator.getRootHash())
                .setFlags(FsVerityDescriptor.FLAG_STORE_MERKLE_TREE_OFFSET)
                .setMerkleTreeOffset(fsvTreeOffset)
                .setCsVersion(FsVerityDescriptor.CODE_SIGN_VERSION);
            FsVerityDescriptorWithSign fsVerityDescriptorWithSign = new FsVerityDescriptorWithSign(fsdbuilder.build(),
                signature);
            byte[] treeBytes = fsVerityGenerator.getTreeBytes();
            ElfSignBlock signBlock = new ElfSignBlock(paddingSize, treeBytes, fsVerityDescriptorWithSign);
            LOGGER.info("Sign elf successfully.");
            return signBlock.toByteArray();
        }
    }

    /**
     * Sign the given hap file, and pack all signature into output file
     *
     * @param input  file to sign
     * @param offset position of codesign block based on start of the file
     * @param inForm file's format
     * @param profileContent profile of the hap
     * @param zip zip
     * @return byte array of code sign block
     * @throws CodeSignException        code signing exception
     * @throws IOException              io error
     * @throws HapFormatException       hap format invalid
     * @throws FsVerityDigestException  computing FsVerity digest error
     * @throws ProfileException         profile of the hap error
     */
    public byte[] getCodeSignBlock(File input, long offset, String inForm, String profileContent, Zip zip)
        throws CodeSignException, IOException, HapFormatException, FsVerityDigestException, ProfileException {
        LOGGER.info("Start to sign code.");
        if (!StringUtils.containsIgnoreCase(SUPPORT_FILE_FORM, inForm)) {
            throw new CodeSignException("file's format is unsupported");
        }
        long dataSize = computeDataSize(zip);
        // generate CodeSignBlock
        this.codeSignBlock = new CodeSignBlock();
        // compute merkle tree offset, replace with computeMerkleTreeOffset if fs-verity descriptor supports
        long fsvTreeOffset = this.codeSignBlock.computeMerkleTreeOffset(offset);
        // update fs-verity segment
        FsVerityInfoSegment fsVerityInfoSegment = new FsVerityInfoSegment(FsVerityDescriptor.VERSION,
            FsVerityGenerator.getFsVerityHashAlgorithm(), FsVerityGenerator.getLog2BlockSize());
        this.codeSignBlock.setFsVerityInfoSegment(fsVerityInfoSegment);

        LOGGER.debug("Sign hap.");
        String ownerID = HapUtils.getAppIdentifier(profileContent);
        createPageInfoExtension(zip);
        try (FileInputStream inputStream = new FileInputStream(input)) {
            Pair<SignInfo, byte[]> hapSignInfoAndMerkleTreeBytesPair = signFile(inputStream, dataSize, true,
                fsvTreeOffset, ownerID);
            // update hap segment in CodeSignBlock
            this.codeSignBlock.getHapInfoSegment().setSignInfo(hapSignInfoAndMerkleTreeBytesPair.getFirst());
            // Insert merkle tree bytes into code sign block
            this.codeSignBlock.addOneMerkleTree(HAP_SIGNATURE_ENTRY_NAME,
                hapSignInfoAndMerkleTreeBytesPair.getSecond());
        }
        // update native lib info segment in CodeSignBlock
        List<Pair<String, SignInfo>> nativeLibInfoList = new ArrayList<>();
        nativeLibInfoList.addAll(signNativeLibs(input, ownerID));
        nativeLibInfoList.addAll(signNativeHnps(input, profileContent, ownerID));
        // update SoInfoSegment in CodeSignBlock
        this.codeSignBlock.getSoInfoSegment().setSoInfoList(nativeLibInfoList);

        // last update codeSignBlock before generating its byte array representation
        updateCodeSignBlock(this.codeSignBlock);

        // complete code sign block byte array here
        byte[] generated = this.codeSignBlock.generateCodeSignBlockByte(fsvTreeOffset);
        LOGGER.info("Sign successfully.");
        return generated;
    }

    private void createPageInfoExtension(Zip zip) {
        long[] bitmapOffSize = PageInfoGenerator.getPageInfoFromZip(zip);
        if (bitmapOffSize.length == 2) {
            pageInfoExtension = new PageInfoExtension(bitmapOffSize[0], bitmapOffSize[1]);
        }
    }

    private long computeDataSize(Zip zip) throws HapFormatException {
        long dataSize = 0L;
        for (ZipEntry entry : zip.getZipEntries()) {
            ZipEntryHeader zipEntryHeader = entry.getZipEntryData().getZipEntryHeader();
            EntryType type = entry.getZipEntryData().getType();
            if (EntryType.BitMap.equals(type) || EntryType.RunnableFile.equals(type)) {
                continue;
            }
            // if the first file is not uncompressed abc or so, set dataSize to zero
            if (entry.getCentralDirectory().getOffset() == 0) {
                break;
            }
            // the first entry which is not abc/so/an is found, return its data offset
            dataSize = entry.getCentralDirectory().getOffset() + ZipEntryHeader.HEADER_LENGTH
                    + zipEntryHeader.getFileNameLength() + zipEntryHeader.getExtraLength();
            break;
        }
        if ((dataSize % CodeSignBlock.PAGE_SIZE_4K) != 0) {
            throw new HapFormatException(
                String.format(Locale.ROOT, "Invalid dataSize(%d), not a multiple of 4096", dataSize));
        }
        return dataSize;
    }

    private List<Pair<String, SignInfo>> signNativeLibs(File input, String ownerID)
        throws IOException, FsVerityDigestException, CodeSignException {
        // sign native files
        try (JarFile inputJar = new JarFile(input, false)) {
            List<String> entryNames = getNativeEntriesFromHap(inputJar);
            if (entryNames.isEmpty()) {
                LOGGER.info("No native libs.");
                return new ArrayList<>();
            }
            return signFilesFromJar(entryNames, inputJar, ownerID);
        }
    }

    private List<Pair<String, SignInfo>> signNativeHnps(File input, String profileContent, String ownerID)
        throws IOException, CodeSignException, ProfileException {
        List<Pair<String, SignInfo>> nativeLibInfoList = new ArrayList<>();
        try (JarFile inputJar = new JarFile(input, false)) {
            Map<String, String> hnpTypeMap = HapUtils.getHnpsFromJson(inputJar);
            // get hnp entry
            for (Enumeration<JarEntry> e = inputJar.entries(); e.hasMoreElements(); ) {
                JarEntry entry = e.nextElement();
                String entryName = entry.getName();
                if (entry.isDirectory() || !entryName.startsWith("hnp/") || !entryName.toLowerCase(Locale.ROOT)
                    .endsWith(".hnp")) {
                    continue;
                }
                String hnpFileName = HapUtils.parseHnpPath(entryName);
                if (!hnpTypeMap.containsKey(hnpFileName)) {
                    throw new CodeSignException("hnp should be described in module.json");
                }
                LOGGER.debug("Sign hnp name = {}", entryName);
                String type = hnpTypeMap.get(hnpFileName);
                String hnpOwnerId = ownerID;
                if ("public".equals(type)) {
                    hnpOwnerId = HapUtils.getPublicHnpOwnerId(profileContent);
                }
                nativeLibInfoList.addAll(signHnpLibs(inputJar, entry, hnpOwnerId));
            }
        }
        return nativeLibInfoList;
    }

    private List<Pair<String, SignInfo>> signHnpLibs(JarFile inputJar, JarEntry hnpEntry, String ownerID)
        throws IOException, CodeSignException {
        Map<String, Long> elfEntries = getElfEntriesFromHnp(inputJar, hnpEntry);
        List<Pair<String, SignInfo>> nativeLibInfoList = elfEntries.entrySet().stream().parallel().map(elf -> {
            String hnpElfPath = hnpEntry.getName() + "!/" + elf.getKey();
            try (InputStream inputStream = inputJar.getInputStream(hnpEntry);
                ZipInputStream hnpInputStream = new ZipInputStream(inputStream)) {
                return signHnpElf(hnpInputStream, hnpElfPath, ownerID, elf);
            } catch (IOException | FsVerityDigestException | CodeSignException e) {
                LOGGER.error("Sign hnp lib error, entry name = {}, msg : {}", hnpElfPath, e.getMessage());
            }
            return null;
        }).collect(Collectors.toList());
        if (nativeLibInfoList.contains(null)) {
            throw new CodeSignException("Sign hnp lib error");
        }
        return nativeLibInfoList;
    }

    /**
     * sign hnp's elf
     *
     * @param hnpInputStream hnp entry input stream
     * @param hnpElfPath hnp's elf path
     * @param ownerID ownerId
     * @param elf elf entry
     * @return native lib info
     * @throws IOException             io error
     * @throws FsVerityDigestException computing FsVerity digest error
     * @throws CodeSignException       code signing exception
     */
    public Pair<String, SignInfo> signHnpElf(ZipInputStream hnpInputStream, String hnpElfPath, String ownerID,
        Map.Entry<String, Long> elf) throws IOException, FsVerityDigestException, CodeSignException {
        java.util.zip.ZipEntry libEntry = null;
        while ((libEntry = hnpInputStream.getNextEntry()) != null) {
            if (elf.getKey().equals(libEntry.getName())) {
                long fileSize = elf.getValue();
                // We don't store merkle tree in code signing of native libs
                // Therefore, the second value of pair returned is ignored
                Pair<SignInfo, byte[]> pairSignInfoAndMerkleTreeBytes = signFile(hnpInputStream, fileSize, false, 0,
                    ownerID);
                return (Pair.create(hnpElfPath, pairSignInfoAndMerkleTreeBytes.getFirst()));
            }
        }
        return null;
    }

    private Map<String, Long> getElfEntriesFromHnp(JarFile inputJar, JarEntry hnpEntry) throws IOException {
        Map<String, Long> elfEntries = new HashMap<>();
        try (InputStream inputStream = inputJar.getInputStream(hnpEntry);
            ZipInputStream hnpInputStream = new ZipInputStream(inputStream)) {
            java.util.zip.ZipEntry libEntry = null;
            while ((libEntry = hnpInputStream.getNextEntry()) != null) {
                byte[] bytes = new byte[4];
                hnpInputStream.read(bytes, 0, 4);
                if (!isElfFile(bytes)) {
                    hnpInputStream.closeEntry();
                    continue;
                }
                // read input stream end to get entry size, can be adjusted based on performance testing
                byte[] tmp = new byte[4096];
                int readLen;
                do {
                    readLen = hnpInputStream.read(tmp, 0, 4096);
                } while (readLen > 0);
                elfEntries.put(libEntry.getName(), libEntry.getSize());
                hnpInputStream.closeEntry();
            }
        }
        return elfEntries;
    }

    /**
     * Get entry name of all native files in hap
     *
     * @param hap the given hap
     * @return list of entry name
     */
    private List<String> getNativeEntriesFromHap(JarFile hap) {
        List<String> result = new ArrayList<>();
        for (Enumeration<JarEntry> e = hap.entries(); e.hasMoreElements();) {
            JarEntry entry = e.nextElement();
            if (!entry.isDirectory()) {
                if (!isNativeFile(entry.getName())) {
                    continue;
                }
                result.add(entry.getName());
            }
        }
        return result;
    }

    /**
     * Check whether the entry is a native file
     *
     * @param entryName the name of entry
     * @return true if it is a native file, and false otherwise
     */
    private boolean isNativeFile(String entryName) {
        if (StringUtils.isEmpty(entryName)) {
            return false;
        }
        if (entryName.endsWith(FileUtils.NATIVE_LIB_AN_SUFFIX)) {
            return true;
        }
        if (entryName.startsWith(FileUtils.LIBS_PATH_PREFIX)) {
            return true;
        }
        return false;
    }

    private boolean isElfFile(byte[] bytes) {
        if (bytes == null || bytes.length != 4) {
            return false;
        }
        return bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46;
    }

    /**
     * Sign specific entries in a hap
     *
     * @param entryNames list of entries which need to be signed
     * @param hap        input hap
     * @param ownerID    app-id in signature to identify
     * @return sign info and merkle tree of each file
     * @throws CodeSignException       sign error
     */
    private List<Pair<String, SignInfo>> signFilesFromJar(List<String> entryNames, JarFile hap, String ownerID)
        throws CodeSignException {
        List<Pair<String, SignInfo>> nativeLibInfoList = entryNames.stream().parallel().map(name -> {
            LOGGER.debug("Sign entry name = {}", name);
            JarEntry inEntry = hap.getJarEntry(name);
            try (InputStream inputStream = hap.getInputStream(inEntry)) {
                long fileSize = inEntry.getSize();
                // We don't store merkle tree in code signing of native libs
                // Therefore, the second value of pair returned is ignored
                Pair<SignInfo, byte[]> pairSignInfoAndMerkleTreeBytes = signFile(inputStream, fileSize, false, 0,
                    ownerID);
                return Pair.create(name, pairSignInfoAndMerkleTreeBytes.getFirst());
            } catch (FsVerityDigestException | CodeSignException | IOException e) {
                LOGGER.error("Sign lib error, entry name = {}, msg : {}", name, e.getMessage());
            }
            return null;
        }).collect(Collectors.toList());
        if (nativeLibInfoList.contains(null)) {
            throw new CodeSignException("Sign lib error");
        }
        return nativeLibInfoList;
    }

    /**
     * Sign a file from input stream
     *
     * @param inputStream   input stream of a file
     * @param fileSize      size of the file
     * @param storeTree     whether to store merkle tree in signed info
     * @param fsvTreeOffset merkle tree raw bytes offset based on the start of file
     * @param ownerID       app-id in signature to identify
     * @return pair of signature and tree
     * @throws FsVerityDigestException computing FsVerity Digest error
     * @throws CodeSignException       signing error
     */
    public Pair<SignInfo, byte[]> signFile(InputStream inputStream, long fileSize, boolean storeTree,
        long fsvTreeOffset, String ownerID) throws FsVerityDigestException, CodeSignException {
        FsVerityGenerator fsVerityGenerator = new FsVerityGenerator();
        fsVerityGenerator.setPageInfoExtension(pageInfoExtension);
        fsVerityGenerator.generateFsVerityDigest(inputStream, fileSize, fsvTreeOffset);
        byte[] fsVerityDigest = fsVerityGenerator.getFsVerityDigest();
        byte[] signature = generateSignature(fsVerityDigest, ownerID);
        int flags = 0;
        if (storeTree) {
            flags = SignInfo.FLAG_MERKLE_TREE_INCLUDED;
        }
        SignInfo signInfo = new SignInfo(fsVerityGenerator.getSaltSize(), flags, fileSize, fsVerityGenerator.getSalt(),
            signature);
        // if store merkle tree in sign info
        if (storeTree) {
            int merkleTreeSize = fsVerityGenerator.getTreeBytes() == null ? 0 : fsVerityGenerator.getTreeBytes().length;
            Extension merkleTreeExtension = new MerkleTreeExtension(merkleTreeSize, fsvTreeOffset,
                fsVerityGenerator.getRootHash());
            signInfo.addExtension(merkleTreeExtension);
            if (pageInfoExtension != null) {
                byte[] fsVerityDigestV2 = fsVerityGenerator.getFsVerityDigestV2();
                byte[] signatureV2 = generateSignature(fsVerityDigestV2, ownerID);
                pageInfoExtension.setSignature(signatureV2);
                signInfo.addExtension(pageInfoExtension);
            }
        }
        return Pair.create(signInfo, fsVerityGenerator.getTreeBytes());
    }

    private byte[] generateSignature(byte[] signedData, String ownerID) throws CodeSignException {
        SignerConfig copiedConfig = signConfig;
        // signConfig is created by SignerFactory
        if ((copiedConfig.getSigner() instanceof LocalSigner)) {
            if (copiedConfig.getCertificates().isEmpty()) {
                throw new CodeSignException("No certificates configured for sign");
            }
            BcSignedDataGenerator bcSignedDataGenerator = new BcSignedDataGenerator();
            bcSignedDataGenerator.setOwnerID(ownerID);
            return bcSignedDataGenerator.generateSignedData(signedData, copiedConfig);
        } else {
            copiedConfig = signConfig.copy();
            BcSignedDataGenerator bcSignedDataGenerator = new BcSignedDataGenerator();
            bcSignedDataGenerator.setOwnerID(ownerID);
            return bcSignedDataGenerator.generateSignedData(signedData, copiedConfig);
        }
    }

    /**
     * At here, segment header, fsverity info/hap/so info segment, merkle tree
     * segment should all be generated.
     * code sign block size, segment number, offset is not updated.
     * Try to update whatever could be updated here.
     *
     * @param codeSignBlock CodeSignBlock
     */
    private void updateCodeSignBlock(CodeSignBlock codeSignBlock) {
        // construct segment header list
        codeSignBlock.setSegmentHeaders();
        // Compute and set segment number
        codeSignBlock.setSegmentNum();
        // update code sign block header flag
        codeSignBlock.setCodeSignBlockFlag();
        // compute segment offset
        codeSignBlock.computeSegmentOffset();
    }

}
