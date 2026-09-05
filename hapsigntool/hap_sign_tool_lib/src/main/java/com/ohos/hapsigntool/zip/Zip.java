/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.error.SignToolErrMsg;
import com.ohos.hapsigntool.error.ZipException;
import com.ohos.hapsigntool.utils.FileUtils;

import com.ohos.hapsigntool.utils.LogUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * resolve zip data
 *
 * @since 2023/12/02
 */
public class Zip {
    private static final LogUtils LOGGER = new LogUtils(Zip.class);

    /**
     * file is uncompress file flag
     */
    public static final short FILE_UNCOMPRESS_METHOD_FLAG = 0;

    /**
     * max comment length
     */
    public static final int MAX_COMMENT_LENGTH = 65535;

    /**
     * max app file length: 200G
     */
    public static final long MAX_APP_FILE_LENGTH = 200 * 1024 * 1024 * 1024L;

    private static final int FILE_ALIGNMENT_BYTES_4K = 4096;

    private static final int RES_FILE_ALIGNMENT_THRESHOLD_BYTES = 1024 * 1024;

    private static final String RES_FILE_PRE_FIX = "resources/resfile/";

    private static final int MAX_CENTRAL_DIRECTORY_NUMBER = 0xFFFF;

    private List<ZipEntry> zipEntries;

    private long signingOffset;

    private byte[] signingBlock;

    private long cDOffset;

    private long eOCDOffset;

    private EndOfCentralDirectory endOfCentralDirectory;

    private String file;

    private boolean isZip64;

    private Zip64Eocd zip64Eocd;

    private Zip64EocdLocator zip64EocdLocator;

    /**
     * create Zip by file
     *
     * @param inputFile file
     */
    public Zip(File inputFile) {
        try {
            this.file = inputFile.getCanonicalPath();
            if (!inputFile.exists()) {
                throw new ZipException("read zip file failed");
            }
            if (inputFile.length() > MAX_APP_FILE_LENGTH) {
                throw new ZipException("read zip file failed, file length exceed 200GB.");
            }
            long start = System.currentTimeMillis();
            // 1. get eocd data
            endOfCentralDirectory = getZipEndOfCentralDirectory(inputFile);
            cDOffset = endOfCentralDirectory.getOffset();
            long eocdEnd = System.currentTimeMillis();
            LOGGER.debug("getZipEndOfCentralDirectory use {} ms", eocdEnd - start);

            // 1.1 check zip64 eocd locator
            // if zip64 eocd locator required
            parseZip64EocdLocator(inputFile);
            if (this.isZip64) {
                parseZip64Eocd(inputFile);
                cDOffset = this.zip64Eocd.getCentralDirectoryOffset();
            }
            // 2. use eocd's cd offset, get cd data
            getZipCentralDirectory(inputFile);
            long cdEnd = System.currentTimeMillis();
            LOGGER.debug("getZipCentralDirectory use {} ms", cdEnd - start);
            // 3. use cd's entry offset and file size, get entry data
            getZipEntries(inputFile);
            ZipEntry endEntry = zipEntries.get(zipEntries.size() - 1);
            CentralDirectory endCD = endEntry.getCentralDirectory();
            ZipEntryData endEntryData = endEntry.getZipEntryData();
            signingOffset = endCD.getOffset() + endEntryData.getLength();
            long entryEnd = System.currentTimeMillis();
            LOGGER.debug("getZipEntries use {} ms", entryEnd - start);
            // 4. file all data - eocd - cd - entry = sign block
            signingBlock = getSigningBlock(inputFile);
        } catch (IOException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, SignToolErrMsg.READ_ZIP_FAILED.toString(e.getMessage()));
        }
    }

    private void parseZip64EocdLocator(File inputFile) throws IOException {
        boolean isZip64EocdLocatorRequired = isZip64EocdLocatorRequired();
        try (RandomAccessFile zipFile = new RandomAccessFile(inputFile, "r")) {
            Optional<Zip64EocdLocator> zip64EocdLocatorOptional = ZipUtils.findZip64EocdLocator(
                    new RandomAccessFileZipDataInput(zipFile), eOCDOffset);
            if (isZip64EocdLocatorRequired) {
                if (!zip64EocdLocatorOptional.isPresent()) {
                    throw new ZipException("parse zip file error, "
                            + "zip64 end of central directory locator is required, but not found.");
                }
                this.isZip64 = true;
                this.zip64EocdLocator = zip64EocdLocatorOptional.get();
            } else {
                if (zip64EocdLocatorOptional.isPresent()) {
                    throw new ZipException("parse zip file error, "
                            + "zip64 end of central directory locator is not required, but found.");
                }
            }
        }
    }

    private void parseZip64Eocd(File inputFile) throws IOException {
        if (!this.isZip64 || this.zip64EocdLocator == null) {
            return;
        }
        long zip64EocdOffset = this.zip64EocdLocator.getZip64EocdOffset();
        if (zip64EocdOffset < 0 || zip64EocdOffset < cDOffset
                || (zip64EocdOffset + Zip64Eocd.MIN_SIZE + Zip64EocdLocator.SIZE) > eOCDOffset) {
            throw new ZipException("parse zip file error, "
                    + "invalid zip64 end of central directory offset: " + zip64EocdOffset);
        }
        try (RandomAccessFile zipFile = new RandomAccessFile(inputFile, "r")) {
            Optional<Zip64Eocd> zip64EocdOptional = ZipUtils.findZip64Eocd(
                    new RandomAccessFileZipDataInput(zipFile), zip64EocdOffset, eOCDOffset);
            if (!zip64EocdOptional.isPresent()) {
                throw new ZipException("parse zip file error, "
                        + "zip64 end of central directory is required, but not found.");
            }
            this.zip64Eocd = zip64EocdOptional.get();
        }
    }

    private boolean isZip64EocdLocatorRequired() {
        return endOfCentralDirectory.getCDTotal() == UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE
                || endOfCentralDirectory.getOffset() == UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE
                || endOfCentralDirectory.getCDSize() == UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE;
    }

    private EndOfCentralDirectory getZipEndOfCentralDirectory(File file) throws IOException {
        if (file.length() < EndOfCentralDirectory.EOCD_LENGTH) {
            throw new ZipException("find zip eocd failed");
        }

        // try to read EOCD without comment
        int eocdLength = EndOfCentralDirectory.EOCD_LENGTH;
        eOCDOffset = file.length() - eocdLength;
        byte[] bytes = FileUtils.readFileByOffsetAndLength(file, eOCDOffset, eocdLength);
        Optional<EndOfCentralDirectory> eocdByBytes = EndOfCentralDirectory.getEOCDByBytes(bytes);
        if (eocdByBytes.isPresent()) {
            return eocdByBytes.get();
        }

        // try to search EOCD with comment
        long eocdMaxLength = Math.min(EndOfCentralDirectory.EOCD_LENGTH + MAX_COMMENT_LENGTH, file.length());
        eOCDOffset = file.length() - eocdMaxLength;
        bytes = FileUtils.readFileByOffsetAndLength(file, eOCDOffset, eocdMaxLength);
        for (int start = 0; start < eocdMaxLength; start++) {
            eocdByBytes = EndOfCentralDirectory.getEOCDByBytes(bytes, start);
            if (eocdByBytes.isPresent()) {
                eOCDOffset += start;
                return eocdByBytes.get();
            }
        }
        throw new ZipException("read zip failed: can not find eocd in file");
    }

    private void getZipCentralDirectory(File file) throws IOException {
        int centralDirectoryCount = getCentralDirectoryCount();
        int centralDirectorySize = getCentralDirectorySize();
        zipEntries = new ArrayList<>(centralDirectoryCount);
        // read full central directory bytes
        byte[] cdBytes = FileUtils.readFileByOffsetAndLength(file, cDOffset, centralDirectorySize);
        if (cdBytes.length != centralDirectorySize) {
            throw new ZipException("find zip cd failed");
        }
        ByteBuffer bf = ByteBuffer.wrap(cdBytes).order(ByteOrder.LITTLE_ENDIAN);
        int offset = 0;
        // one by one format central directory
        while (offset < cdBytes.length) {
            CentralDirectory cd = CentralDirectory.getCentralDirectory(bf);
            ZipEntry entry = new ZipEntry();
            entry.setCentralDirectory(cd);
            zipEntries.add(entry);
            offset += cd.getLength();
        }
        long exceptEocdOffset = offset + cDOffset;
        if (isZip64) {
            exceptEocdOffset += zip64Eocd.getSize();
            exceptEocdOffset += Zip64EocdLocator.SIZE;
        }
        if (exceptEocdOffset != eOCDOffset) {
            throw new ZipException("excepted eocd offset not equals to actual eocd offset");
        }
    }

    private int getCentralDirectoryCount() throws ZipException {
        if (isZip64) {
            long totalEntries = this.zip64Eocd.getTotalEntries();
            if (totalEntries > Integer.MAX_VALUE) {
                throw new ZipException("parse zip central directory failed, " +
                        "total number of central directory records " + totalEntries + " out of range.");
            }
            return (int) totalEntries;
        }
        int cdTotal = endOfCentralDirectory.getCDTotal();
        if (cdTotal < 0) {
            throw new ZipException("invalid CD total count: " + cdTotal);
        }
        if (cdTotal >= UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE) {
            throw new ZipException("CD total count indicates zip64 but file is not zip64 format");
        }
        return cdTotal;
    }

    private int getCentralDirectorySize() throws ZipException {
        long centralDirectorySize = endOfCentralDirectory.getCDSize();
        if (!isZip64 && centralDirectorySize >= UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE) {
            throw new ZipException("CD size indicates zip64 but file is not zip64 format");
        }
        if (isZip64) {
            centralDirectorySize = this.zip64Eocd.getCentralDirectorySize();
        }
        if (centralDirectorySize > Integer.MAX_VALUE) {
            throw new ZipException("parse zip central directory failed, " +
                    "central directory size " + centralDirectorySize + " out of range.");
        }
        return (int) centralDirectorySize;
    }

    private byte[] getSigningBlock(File file) throws IOException {
        long size = cDOffset - signingOffset;
        if (size < 0) {
            throw new ZipException("signing offset in front of entry end");
        }
        if (size == 0) {
            return new byte[0];
        }
        return FileUtils.readFileByOffsetAndLength(file, signingOffset, size);
    }

    private void getZipEntries(File file) throws IOException {
        // use central directory data, find entry data
        for (ZipEntry entry : zipEntries) {
            CentralDirectory cd = entry.getCentralDirectory();
            long offset = cd.getOffset();
            long unCompressedSize = cd.getUnCompressedSize();
            long compressedSize = cd.getCompressedSize();
            long fileSize = cd.getMethod() == FILE_UNCOMPRESS_METHOD_FLAG ? unCompressedSize : compressedSize;

            ZipEntryData zipEntryData = ZipEntryData.getZipEntry(file, offset, fileSize);
            if (cDOffset - offset < zipEntryData.getLength()) {
                throw new ZipException("cd offset in front of entry end");
            }
            entry.setZipEntryData(zipEntryData);
        }
    }

    /**
     * output zip to zip file
     *
     * @param outFile file path
     */
    public void toFile(String outFile) {
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            for (ZipEntry entry : zipEntries) {
                ZipEntryData zipEntryData = entry.getZipEntryData();
                FileUtils.writeByteToOutFile(zipEntryData.getZipEntryHeader().toBytes(), fos);
                boolean isSuccess;
                if (entry.getZipEntryData().getData() != null) {
                    ByteBuffer bf = ByteBuffer.wrap(entry.getZipEntryData().getData());
                    bf.order(ByteOrder.LITTLE_ENDIAN);
                    isSuccess = FileUtils.writeByteToOutFile(bf.array(), fos);
                } else {
                    isSuccess = FileUtils.appendWriteFileByOffsetToFile(file, fos,
                            zipEntryData.getFileOffset(), zipEntryData.getFileSize());
                }
                if (!isSuccess) {
                    throw new ZipException("write zip data failed");
                }
                if (zipEntryData.getDataDescriptor() != null) {
                    FileUtils.writeByteToOutFile(zipEntryData.getDataDescriptor().toBytes(), fos);
                }
            }
            if (signingBlock != null) {
                FileUtils.writeByteToOutFile(signingBlock, fos);
            }
            for (ZipEntry entry : zipEntries) {
                CentralDirectory cd = entry.getCentralDirectory();
                FileUtils.writeByteToOutFile(cd.toBytes(), fos);
            }
            if (isZip64) {
                FileUtils.writeByteToOutFile(zip64Eocd.toBytes(), fos);
                FileUtils.writeByteToOutFile(zip64EocdLocator.toBytes(), fos);
            }
            FileUtils.writeByteToOutFile(endOfCentralDirectory.toBytes(), fos);
        } catch (IOException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, SignToolErrMsg.WRITE_ZIP_FAILED.toString(e.getMessage()));
        }
    }

    /**
     * alignment uncompress entry
     *
     * @param alignment int alignment
     */
    public void alignment(int alignment) {
        try {
            sort();
            boolean isFirstUnRunnableFile = true;
            for (ZipEntry entry : zipEntries) {
                ZipEntryData zipEntryData = entry.getZipEntryData();
                short method = zipEntryData.getZipEntryHeader().getMethod();
                if (method != FILE_UNCOMPRESS_METHOD_FLAG && !isFirstUnRunnableFile) {
                    // only align uncompressed entry and the first unrunnable entry.
                    break;
                }
                int alignBytes;
                EntryType type = Optional.of(zipEntryData).map(ZipEntryData::getType).orElse(null);
                long fileSize = Optional.of(zipEntryData).map(ZipEntryData::getFileSize).orElse(0L);
                String fileName = Optional.of(zipEntryData).map(ZipEntryData::getZipEntryHeader)
                        .map(ZipEntryHeader::getFileName).orElse("");
                if ((type == EntryType.RUNNABLE_FILE && method == FILE_UNCOMPRESS_METHOD_FLAG) ||
                    type == EntryType.BIT_MAP) {
                    // .abc and .so file align 4096 byte.
                    alignBytes = FILE_ALIGNMENT_BYTES_4K;
                } else if (isFirstUnRunnableFile) {
                    // the first file after runnable file, align 4096 byte.
                    alignBytes = FILE_ALIGNMENT_BYTES_4K;
                    isFirstUnRunnableFile = false;
                } else if (fileName.startsWith(RES_FILE_PRE_FIX) && fileSize >= RES_FILE_ALIGNMENT_THRESHOLD_BYTES) {
                    // resource file whose size larger than or equal to 1MB align 4096 byte.
                    alignBytes = FILE_ALIGNMENT_BYTES_4K;
                } else {
                    // normal file align 4 byte.
                    alignBytes = alignment;
                }
                int add = entry.alignment(alignBytes);
                if (add > 0) {
                    resetOffset();
                }
            }
        } catch (ZipException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, SignToolErrMsg.ALIGNMENT_ZIP_FAILED
                    .toString(e.getMessage()));
        }
    }

    /**
     * add bit map entry
     *
     * @param data bitmap data
     * @throws ZipException ZipException
     */
    public void addBitMap(byte[] data) throws ZipException {
        zipEntries.removeIf(e -> e.getZipEntryData().getType() == EntryType.BIT_MAP);
        ZipEntry entry = new ZipEntry.Builder().setMethod(FILE_UNCOMPRESS_METHOD_FLAG)
                .setUncompressedSize(data.length)
                .setCompressedSize(data.length)
                .setFileName(FileUtils.BIT_MAP_FILENAME)
                .setData(data)
                .build();
        zipEntries.add(entry);
    }

    /**
     * remove sign block
     *
     * @throws ZipException if remove sign block failed
     */
    public void removeSignBlock() throws ZipException {
        signingBlock = null;
        resetOffset();
    }

    /**
     * Sort uncompress entry in the front.
     *
     * @throws ZipException sort entry failed
     */
    private void sort() throws ZipException {
        // sort uncompress file (so, abc, an) - bitmap - other uncompress file - compress file
        zipEntries.sort((entry1, entry2) -> {
            short entry1Method = entry1.getZipEntryData().getZipEntryHeader().getMethod();
            short entry2Method = entry2.getZipEntryData().getZipEntryHeader().getMethod();
            String entry1FileName = entry1.getZipEntryData().getZipEntryHeader().getFileName();
            String entry2FileName = entry2.getZipEntryData().getZipEntryHeader().getFileName();
            if (entry1Method == FILE_UNCOMPRESS_METHOD_FLAG && entry2Method == FILE_UNCOMPRESS_METHOD_FLAG) {
                EntryType entry1Type = entry1.getZipEntryData().getType();
                EntryType entry2Type = entry2.getZipEntryData().getType();
                if (entry1Type != entry2Type) {
                    return entry1Type.compareTo(entry2Type);
                }
                return entry1FileName.compareTo(entry2FileName);
            } else if (entry1Method == FILE_UNCOMPRESS_METHOD_FLAG) {
                return -1;
            } else if (entry2Method == FILE_UNCOMPRESS_METHOD_FLAG) {
                return 1;
            }
            return entry1FileName.compareTo(entry2FileName);
        });
        resetOffset();
    }

    private void resetOffset() throws ZipException {
        long offset = 0L;
        long cdLength = 0L;
        for (ZipEntry entry : zipEntries) {
            entry.updateLength();
            entry.getCentralDirectory().updateOffset(offset);
            offset += entry.getZipEntryData().getLength();
            cdLength += entry.getCentralDirectory().getLength();
        }
        if (signingBlock != null) {
            offset += signingBlock.length;
        }
        updateEocd(offset, cdLength);
    }

    private void updateEocd(long newCdOffset, long newCdSize) {
        cDOffset = newCdOffset;
        eOCDOffset = newCdOffset + newCdSize;
        if (isZip64) {
            zip64Eocd.setCentralDirectoryOffset(newCdOffset);
            zip64Eocd.setCentralDirectorySize(newCdSize);
            zip64Eocd.setTotalEntries(zipEntries.size());
            zip64Eocd.setEntriesOnDisk(zipEntries.size());
            zip64EocdLocator.setZip64EocdOffset(newCdOffset + newCdSize);
            eOCDOffset += zip64Eocd.getSize();
            eOCDOffset += Zip64EocdLocator.SIZE;
            endOfCentralDirectory.toZip64Format();
            return;
        }
        if (newCdOffset >= UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE
                || newCdSize >= UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE
                || zipEntries.size() >= UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE) {
            // need zip64 format
            zip64Eocd = createZip64Eocd();
            zip64Eocd.setCentralDirectoryOffset(newCdOffset);
            zip64Eocd.setCentralDirectorySize(newCdSize);
            zip64Eocd.setTotalEntries(zipEntries.size());
            zip64Eocd.setEntriesOnDisk(zipEntries.size());
            zip64EocdLocator = createZip64EocdLocator();
            zip64EocdLocator.setZip64EocdOffset(newCdOffset + newCdSize);
            isZip64 = true;
            eOCDOffset += zip64Eocd.getSize();
            eOCDOffset += Zip64EocdLocator.SIZE;
            endOfCentralDirectory.toZip64Format();
            return;
        }
        endOfCentralDirectory.setOffset(newCdOffset);
        endOfCentralDirectory.setCDSize(newCdSize);
        endOfCentralDirectory.setCDTotal(zipEntries.size());
        endOfCentralDirectory.setThisDiskCDNum(zipEntries.size());
    }

    private Zip64Eocd createZip64Eocd() {
        Zip64Eocd newZip64Eocd = new Zip64Eocd();
        newZip64Eocd.setDiskNumberOfCdStart(endOfCentralDirectory.getcDStartDiskNum());
        newZip64Eocd.setDiskNumber(endOfCentralDirectory.getDiskNum());
        newZip64Eocd.setVersionNeeded((short) 45);
        newZip64Eocd.setVersionMadeBy((short) 45);
        newZip64Eocd.setRecordSize(Zip64Eocd.MIN_RECORD_SIZE);
        return newZip64Eocd;
    }

    private Zip64EocdLocator createZip64EocdLocator() {
        Zip64EocdLocator newZip64EocdLocator = new Zip64EocdLocator();
        newZip64EocdLocator.setDiskNumberOfZip64Eocd(endOfCentralDirectory.getcDStartDiskNum());
        newZip64EocdLocator.setTotalNumberOfDisk(endOfCentralDirectory.getDiskNum());
        return newZip64EocdLocator;
    }

    public List<ZipEntry> getZipEntries() {
        return zipEntries;
    }

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public boolean isZip64() {
        return isZip64;
    }
}