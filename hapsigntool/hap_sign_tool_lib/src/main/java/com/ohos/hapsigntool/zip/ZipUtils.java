/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.zip;

import com.ohos.hapsigntool.entity.Pair;
import com.ohos.hapsigntool.error.HapFormatException;
import com.ohos.hapsigntool.error.SignToolErrMsg;
import com.ohos.hapsigntool.error.ZipException;
import com.ohos.hapsigntool.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;
import java.util.zip.ZipFile;

/**
 * Utils functions of zip-files.
 *
 * @since 2021/12/22
 */
public class ZipUtils {
    private static final int ZIP_EOCD_SEGMENT_MIN_SIZE = 22;

    private static final int ZIP_EOCD_SEGMENT_FLAG = 0x06054b50;

    private static final int ZIP_CENTRAL_DIR_COUNT_OFFSET_IN_EOCD = 10;

    private static final int ZIP_CENTRAL_DIR_SIZE_OFFSET_IN_EOCD = 12;

    private static final int ZIP_CENTRAL_DIR_OFFSET_IN_EOCD = 16;

    private static final int ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20;

    private static final int UINT16_MAX_VALUE = 0xffff;

    private static final long UINT32_MAX_VALUE = 0xffffffffL;

    /**
     * Constructor of Method
     */
    private ZipUtils() {
    }

    /**
     * This function find Eocd by searching Eocd flag from input buffer(searchBuffer) and
     * making sure the comment length is equal to the expected value
     *
     * @param searchBuffer data buffer used to search EOCD.
     * @return offset from buffer start point.
     */
    public static int findEocdInSearchBuffer(ByteBuffer searchBuffer) {
        checkBufferIsLittleEndian(searchBuffer);
        /*
         * Eocd format:
         * 4-bytes: End of central directory flag
         * 2-bytes: Number of this disk
         * 2-bytes: Number of the disk with the start of central directory
         * 2-bytes: Total number of entries in the central directory on this disk
         * 2-bytes: Total number of entries in the central directory
         * 4-bytes: Size of central directory
         * 4-bytes: offset of central directory in zip file
         * 2-bytes: ZIP file comment length, the value n is in the range of [0, 65535]
         * n-bytes: ZIP Comment block data
         */
        int searchBufferSize = searchBuffer.capacity();
        if (searchBufferSize < ZIP_EOCD_SEGMENT_MIN_SIZE) {
            return -1;
        }

        int currentOffset = searchBufferSize - ZIP_EOCD_SEGMENT_MIN_SIZE;
        while (currentOffset >= 0) {
            if (searchBuffer.getInt(currentOffset) == ZIP_EOCD_SEGMENT_FLAG) {
                int commentLength = getUInt16FromBuffer(searchBuffer, currentOffset + ZIP_EOCD_COMMENT_LENGTH_OFFSET);
                int expectedCommentLength = searchBufferSize - ZIP_EOCD_SEGMENT_MIN_SIZE - currentOffset;
                if (commentLength == expectedCommentLength) {
                    return currentOffset;
                }
            }
            currentOffset--;
        }
        return -1;
    }

    /**
     * Check whether the zip is zip64 by finding ZIP64 End of Central Directory Locator.
     * ZIP64 End of Central Directory Locator immediately precedes the ZIP End of Central Directory.
     *
     * @param zip object of RandomAccessFile for zip-file.
     * @param zipEocdOffset offset of the ZIP EOCD in the file.
     * @return true, if ZIP64 End of Central Directory Locator is present.
     * @throws IOException read file error.
     */
    public static boolean checkZip64EoCDLocatorIsPresent(ZipDataInput zip, long zipEocdOffset) throws IOException {
        return findZip64EocdLocator(zip, zipEocdOffset).isPresent();
    }

    /**
     * Find zip64 end of central directory locator.
     *
     * @param zip input zip file
     * @param zipEocdOffset zip end of central directory offset
     * @return zip64 end of central directory locator
     * @throws IOException read file error
     */
    public static Optional<Zip64EocdLocator> findZip64EocdLocator(ZipDataInput zip, long zipEocdOffset)
            throws IOException {
        long locatorPos = zipEocdOffset - Zip64EocdLocator.SIZE;
        if (locatorPos < 0) {
            return Optional.empty();
        }
        ByteBuffer buffer = zip.createByteBuffer(locatorPos, Zip64EocdLocator.SIZE).order(ByteOrder.LITTLE_ENDIAN);
        int signature = buffer.getInt(0);
        if (signature != Zip64EocdLocator.SIGNATURE) {
            return Optional.empty();
        }
        return Optional.of(Zip64EocdLocator.parse(buffer));
    }

    /**
     * Find zip64 end of central directory.
     *
     * @param zip input zip file
     * @param zip64EocdOffset zip64 end of central directory offset
     * @param eocdOffset zip end of central directory offset
     * @return zip64 end of central directory
     * @throws IOException find zip64 end of central directory error
     */
    public static Optional<Zip64Eocd> findZip64Eocd(ZipDataInput zip, long zip64EocdOffset, long eocdOffset)
            throws IOException {
        if ((zip.size() - Zip64Eocd.MIN_SIZE) < zip64EocdOffset) {
            return Optional.empty();
        }
        ByteBuffer buffer = zip.createByteBuffer(zip64EocdOffset, Zip64Eocd.MIN_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        int signature = buffer.getInt(0);
        if (signature != Zip64Eocd.SIGNATURE) {
            return Optional.empty();
        }
        Zip64Eocd zip64Eocd = Zip64Eocd.parse(buffer);
        long recordSize = zip64Eocd.getRecordSize();
        if (recordSize < Zip64Eocd.MIN_RECORD_SIZE) {
            throw new ZipException("invalid zip64 record size: " + recordSize);
        }
        if (recordSize > Zip64Eocd.MIN_RECORD_SIZE) {
            // parse extensible data
            long zip64ExtensibleDataSize = recordSize - Zip64Eocd.MIN_RECORD_SIZE;
            if (zip64ExtensibleDataSize > Integer.MAX_VALUE) {
                throw new ZipException("parse end of central directory error, "
                        + "expected zip64 extensible data size out of range: " + zip64ExtensibleDataSize);
            }
            long zip64ExtensibleDataOffset = zip64EocdOffset + Zip64Eocd.MIN_SIZE;
            long expectedOffset = eocdOffset - Zip64EocdLocator.SIZE - zip64ExtensibleDataSize;
            if (expectedOffset != zip64ExtensibleDataOffset) {
                throw new ZipException("parse end of central directory error, expected zip64 extensible data offset("
                        + expectedOffset + ") not equals actual offset(" + zip64ExtensibleDataOffset + ").");
            }
            ByteBuffer byteBuffer = zip.createByteBuffer(zip64ExtensibleDataOffset, (int) zip64ExtensibleDataSize);
            byte[] zip64ExtensibleData = new byte[(int) zip64ExtensibleDataSize];
            byteBuffer.get(zip64ExtensibleData);
            zip64Eocd.setZip64ExtensibleData(zip64ExtensibleData);
        }
        return Optional.of(zip64Eocd);
    }

    /**
     * Get offset value of Central Directory from End of Central Directory Record.
     *
     * @param eocd buffer of End of Central Directory Record
     * @return offset value of Central Directory.
     */
    public static long getCentralDirectoryOffset(ByteBuffer eocd) {
        checkBufferIsLittleEndian(eocd);
        return getUInt32FromBuffer(eocd, eocd.position() + ZIP_CENTRAL_DIR_OFFSET_IN_EOCD);
    }

    /**
     * set offset value of Central Directory to End of Central Directory Record.
     *
     * @param eocd buffer of End of Central Directory Record.
     * @param offset offset value of Central Directory.
     */
    public static void setCentralDirectoryOffset(ByteBuffer eocd, long offset) {
        checkBufferIsLittleEndian(eocd);
        setUInt32ToBuffer(eocd, eocd.position() + ZIP_CENTRAL_DIR_OFFSET_IN_EOCD, offset);
    }

    /**
     * Get size of Central Directory from End of Central Directory Record.
     *
     * @param eocd buffer of End of Central Directory Record.
     * @return size of Central Directory.
     */
    public static long getCentralDirectorySize(ByteBuffer eocd) {
        checkBufferIsLittleEndian(eocd);
        return getUInt32FromBuffer(eocd, eocd.position() + ZIP_CENTRAL_DIR_SIZE_OFFSET_IN_EOCD);
    }

    /**
     * Get total count of Central Directory from End of Central Directory Record.
     *
     * @param eocd buffer of End of Central Directory Record.
     * @return size of Central Directory.
     */
    public static int getCentralDirectoryCount(ByteBuffer eocd) {
        checkBufferIsLittleEndian(eocd);
        return getUInt16FromBuffer(eocd, eocd.position() + ZIP_CENTRAL_DIR_COUNT_OFFSET_IN_EOCD);
    }

    /**
     * Read the specific entry content from zip file.
     *
     * @param entryName entry name
     * @param zipFile input zip file
     * @return entry content
     * @throws IOException if an I/O error has occurred
     */
    public static byte[] getZipEntryContent(String entryName, File zipFile) throws IOException {
        try (ZipFile zip = new ZipFile(zipFile)) {
            java.util.zip.ZipEntry zipEntry = zip.getEntry(entryName);
            if (zipEntry == null) {
                return new byte[0];
            }
            try (InputStream inputStream = zip.getInputStream(zipEntry)) {
                if (inputStream == null) {
                    return new byte[0];
                }
                return FileUtils.read(inputStream);
            }
        }
    }

    private static void checkBufferIsLittleEndian(ByteBuffer buffer) {
        if (buffer.order() == ByteOrder.LITTLE_ENDIAN) {
            return;
        }
        throw new IllegalArgumentException("ByteBuffer is not little endian");
    }

    static int getUInt16FromBuffer(ByteBuffer buffer, int offset) {
        return buffer.getShort(offset) & 0xffff;
    }

    static long getUInt32FromBuffer(ByteBuffer buffer, int offset) {
        return buffer.getInt(offset) & UINT32_MAX_VALUE;
    }

    private static void setUInt32ToBuffer(ByteBuffer buffer, int offset, long value) {
        if ((value < 0) || (value > UINT32_MAX_VALUE)) {
            throw new IllegalArgumentException("uint32 value of out range: " + value);
        }
        buffer.putInt(buffer.position() + offset, (int) value);
    }

    /**
     * Find the key information for parsing the zip file.
     *
     * @param in zip file
     * @return the key information for parsing the zip file.
     * @throws IOException file operation error
     * @throws HapFormatException hap file format error
     */
    public static ZipFileInfo findZipInfo(ZipDataInput in) throws IOException, HapFormatException {
        Pair<Long, EndOfCentralDirectory> eocdOffsetAndBuffer = findEocdInHap(in);
        if (eocdOffsetAndBuffer == null) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP End of Central Directory not found"));
        }
        long eocdOffset = eocdOffsetAndBuffer.getFirst();
        EndOfCentralDirectory eocd = eocdOffsetAndBuffer.getSecond();
        long cdStartOffset = eocd.getOffset();
        long cdSize = eocd.getCDSize();
        int cdCount = eocd.getCDTotal();
        boolean needZip64Format = needZip64Format(cdStartOffset, cdSize, cdCount);
        if (needZip64Format) {
            return findZip64FileInfo(in, eocd, eocdOffset);
        }
        // no need zip64 format, but actually use zip64 format
        Optional<Zip64EocdLocator> zip64EocdLocator = findZip64EocdLocator(in, eocdOffset);
        if (zip64EocdLocator.isPresent()) {
            return findZip64FileInfo(in, eocd, zip64EocdLocator.get(), eocdOffset);
        }
        // normal zip format
        long cdEndOffset = cdStartOffset + cdSize;
        if (cdEndOffset != eocdOffset) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP Central Directory end offset(" + cdEndOffset + ") "
                            + " different from ZIP End of Central Directory offset(" + eocdOffset + ")"));
        }
        if (cdSize > Integer.MAX_VALUE) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP Central Directory size out of range: " + cdSize));
        }
        return new ZipFileInfo(cdStartOffset, (int) cdSize, cdCount, eocdOffset, eocd);
    }

    private static ZipFileInfo findZip64FileInfo(ZipDataInput in, EndOfCentralDirectory eocd,
            Zip64EocdLocator zip64EocdLocator, long eocdOffset) throws IOException, HapFormatException {
        long zip64EocdOffset = zip64EocdLocator.getZip64EocdOffset();
        Optional<Zip64Eocd> zip64EocdOptional = findZip64Eocd(in, zip64EocdOffset, eocdOffset);
        if (!zip64EocdOptional.isPresent()) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("parse zip file error, zip64 end of central directory is required, "
                            + "but not found."));
        }
        long cdStartOffset = zip64EocdOptional.get().getCentralDirectoryOffset();
        long cdSize = zip64EocdOptional.get().getCentralDirectorySize();
        if (cdSize < 0 || cdStartOffset < 0 || cdSize > Long.MAX_VALUE - cdStartOffset) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP Central Directory offset/size overflow"));
        }
        long cdEndOffset = cdStartOffset + cdSize;
        if (cdEndOffset != zip64EocdOffset) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP Central Directory end offset(" + cdEndOffset + ") "
                            + " different from ZIP64 End of Central Directory offset(" + zip64EocdOffset + ")"));
        }
        if (cdSize > Integer.MAX_VALUE) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP Central Directory size out of range: " + cdSize));
        }
        long cdCount = zip64EocdOptional.get().getTotalEntries();
        if (cdCount > Integer.MAX_VALUE) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("ZIP Central Directory record number out of range: " + cdCount));
        }
        ZipFileInfo zipFileInfo = new ZipFileInfo(cdStartOffset, (int) cdSize, (int) cdCount, eocdOffset, eocd);
        zipFileInfo.setZip64(true);
        zipFileInfo.setZip64Eocd(zip64EocdOptional.get());
        zipFileInfo.setZip64EocdLocator(zip64EocdLocator);
        return zipFileInfo;
    }

    private static ZipFileInfo findZip64FileInfo(ZipDataInput in, EndOfCentralDirectory eocd, long eocdOffset)
            throws IOException, HapFormatException {
        Optional<Zip64EocdLocator> zip64EocdLocatorOp = findZip64EocdLocator(in, eocdOffset);
        if (!zip64EocdLocatorOp.isPresent()) {
            throw new HapFormatException(SignToolErrMsg.ZIP_FORMAT_FAILED
                    .toString("parse zip file error, zip64 end of central directory locator is required, "
                            + "but not found."));
        }
        return findZip64FileInfo(in, eocd, zip64EocdLocatorOp.get(), eocdOffset);
    }

    private static boolean needZip64Format(long cdStartOffset, long cdSize, long cdCount) {
        return cdStartOffset == UINT32_MAX_VALUE || cdSize == UINT32_MAX_VALUE || cdCount == UINT16_MAX_VALUE;
    }

    private static Pair<Long, EndOfCentralDirectory> findEocdInHap(ZipDataInput in) throws IOException {
        Pair<Long, EndOfCentralDirectory> eocdInHap = findEocdInHap(in, 0);
        if (eocdInHap != null) {
            return eocdInHap;
        }
        return findEocdInHap(in, UINT16_MAX_VALUE);
    }

    private static Pair<Long, EndOfCentralDirectory> findEocdInHap(ZipDataInput zip, int maxCommentSize)
            throws IOException {
        if ((maxCommentSize < 0) || (maxCommentSize > UINT16_MAX_VALUE)) {
            throw new IllegalArgumentException("maxCommentSize: " + maxCommentSize);
        }
        long fileSize = zip.size();
        if (fileSize < ZIP_EOCD_SEGMENT_MIN_SIZE) {
            throw new IllegalArgumentException("file length " + fileSize + " is too smaller");
        }
        int finalMaxCommentSize = (int) Math.min(maxCommentSize, fileSize - ZIP_EOCD_SEGMENT_MIN_SIZE);
        int searchBufferSize = finalMaxCommentSize + ZIP_EOCD_SEGMENT_MIN_SIZE;
        long bufferOffsetInFile = fileSize - searchBufferSize;
        ByteBuffer searchEocdBuffer = zip.createByteBuffer(bufferOffsetInFile, searchBufferSize);
        searchEocdBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int eocdOffsetInSearchBuffer = findEocdInSearchBuffer(searchEocdBuffer);
        if (eocdOffsetInSearchBuffer == -1) {
            return null;
        }
        searchEocdBuffer.position(eocdOffsetInSearchBuffer);
        ByteBuffer eocdBuffer = searchEocdBuffer.slice().order(ByteOrder.LITTLE_ENDIAN);
        Optional<EndOfCentralDirectory> eocdOption = EndOfCentralDirectory.parse(eocdBuffer);
        return eocdOption.map(eocd -> Pair.create(bufferOffsetInFile + eocdOffsetInSearchBuffer, eocd))
                .orElse(null);
    }
}