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

package com.ohos.hapsigntool.codesigning.fsverity;

import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.utils.DigestUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

/**
 * FsVerity data generator supper class
 *
 * @since 2023/06/05
 */
public class FsVerityGenerator {
    /**
     * FsVerity hash algorithm
     */
    private static final FsVerityHashAlgorithm FS_VERITY_HASH_ALGORITHM = FsVerityHashAlgorithm.SHA256;

    private static final byte LOG_2_OF_FSVERITY_HASH_PAGE_SIZE = 12;

    /**
     * salt for hashing one page
     */
    protected byte[] salt = null;

    private byte[] fsVerityDigest = null;

    private byte[] treeBytes = null;

    private byte[] rootHash = null;

    /**
     * generate merkle tree of given input
     *
     * @param inputStream           input stream for generate merkle tree
     * @param size                  total size of input stream
     * @param fsVerityHashAlgorithm hash algorithm for FsVerity
     * @return merkle tree
     * @throws FsVerityDigestException if error
     */
    public MerkleTree generateMerkleTree(InputStream inputStream, long size,
        FsVerityHashAlgorithm fsVerityHashAlgorithm) throws FsVerityDigestException {
        MerkleTree merkleTree;
        try (MerkleTreeBuilder builder = new MerkleTreeBuilder()) {
            merkleTree = builder.generateMerkleTree(inputStream, size, fsVerityHashAlgorithm);
        } catch (IOException e) {
            throw new FsVerityDigestException("IOException: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new FsVerityDigestException("Invalid algorithm:" + e.getMessage());
        }
        return merkleTree;
    }

    /**
     * generate FsVerity digest of given input
     *
     * @param inputStream   input stream for generate FsVerity digest
     * @param size          total size of input stream
     * @param fsvTreeOffset merkle tree raw bytes offset based on the start of file
     * @throws FsVerityDigestException if error
     */
    public void generateFsVerityDigest(InputStream inputStream, long size, long fsvTreeOffset)
        throws FsVerityDigestException {
        MerkleTree merkleTree;
        if (size == 0) {
            merkleTree = new MerkleTree(null, null, FS_VERITY_HASH_ALGORITHM);
        } else {
            merkleTree = generateMerkleTree(inputStream, size, FS_VERITY_HASH_ALGORITHM);
        }
        int flags = fsvTreeOffset == 0 ? 0 : FsVerityDescriptor.FLAG_STORE_MERKLE_TREE_OFFSET;
        // sign size is 0, cs version is 0
        FsVerityDescriptor.Builder builder = new FsVerityDescriptor.Builder().setFileSize(size)
            .setHashAlgorithm(FS_VERITY_HASH_ALGORITHM.getId())
            .setLog2BlockSize(LOG_2_OF_FSVERITY_HASH_PAGE_SIZE)
            .setSaltSize((byte) getSaltSize())
            .setSalt(salt)
            .setRawRootHash(merkleTree.rootHash)
            .setFlags(flags)
            .setMerkleTreeOffset(fsvTreeOffset);
        byte[] fsVerityDescriptor = builder.build().getByteForGenerateDigest();
        byte[] digest;
        try {
            digest = DigestUtils.computeDigest(fsVerityDescriptor, FS_VERITY_HASH_ALGORITHM.getHashAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new FsVerityDigestException("Invalid algorithm" + e.getMessage(), e);
        }
        fsVerityDigest = FsVerityDigest.getFsVerityDigest(FS_VERITY_HASH_ALGORITHM.getId(), digest);
        treeBytes = merkleTree.tree;
        rootHash = merkleTree.rootHash;
    }

    /**
     * Get FsVerity digest
     *
     * @return bytes of FsVerity digest
     */
    public byte[] getFsVerityDigest() {
        return fsVerityDigest;
    }

    /**
     * Get merkle tree in bytes
     *
     * @return bytes of merkle tree
     */
    public byte[] getTreeBytes() {
        return treeBytes;
    }

    /**
     * Get merkle tree rootHash in bytes
     *
     * @return bytes of merkle tree rootHash
     */
    public byte[] getRootHash() {
        return rootHash;
    }

    public byte[] getSalt() {
        return salt;
    }

    /**
     * Returns byte size of salt
     *
     * @return byte size of salt
     */
    public int getSaltSize() {
        return this.salt == null ? 0 : this.salt.length;
    }

    /**
     * Returns the id of fs-verity hash algorithm
     *
     * @return fs-verity hash algorithm id
     */
    public static byte getFsVerityHashAlgorithm() {
        return FS_VERITY_HASH_ALGORITHM.getId();
    }

    /**
     * Returns the log2 of size of data and tree blocks
     *
     * @return log2 of size of data and tree blocks
     */
    public static byte getLog2BlockSize() {
        return LOG_2_OF_FSVERITY_HASH_PAGE_SIZE;
    }
}