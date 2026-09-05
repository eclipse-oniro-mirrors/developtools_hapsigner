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

package com.ohos.hapsigntool.zip;

import com.ohos.hapsigntool.error.ZipException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Zip64 end of central directory record.
 * zip64 end of central directory record signature    4 bytes (0x06064b50)
 * size of zip64 end of central directory record      8 bytes
 * version made by                                    2 bytes
 * version needed to extract                          2 bytes
 * number of this disk                                4 bytes
 * disk where central directory starts                4 bytes
 * number of central directory records on this disk   8 bytes
 * total number of central directory records          8 bytes
 * size of central directory                          8 bytes
 * offset of start of central directory               8 bytes
 * zip64 extensible data sector                       variable bytes
 *
 * @since 2026-08-10
 */
public class Zip64Eocd {
    /**
     * zip64 end of central directory signature.
     */
    public static final int SIGNATURE = 0x06064b50;

    /**
     * zip64 end of central directory min size.
     */
    public static final int MIN_SIZE = 56;

    /**
     * zip64 end of central directory min record size.
     */
    public static final long MIN_RECORD_SIZE = MIN_SIZE - 12;

    private static final int RECORD_SIZE_END_OFFSET = 12;

    private long recordSize;
    private short versionMadeBy;
    private short versionNeeded;
    private int diskNumber;
    private int diskNumberOfCdStart;
    private long entriesOnDisk;
    private long totalEntries;
    private long centralDirectorySize;
    private long centralDirectoryOffset;
    private byte[] zip64ExtensibleData;

    /**
     * Parse zip64 end of central directory from the specific byte buffer.
     *
     * @param byteBuffer the specific byte buffer
     * @return zip64 end of central directory
     * @throws ZipException if parsing zip64 end of central directory error
     */
    public static Zip64Eocd parse(ByteBuffer byteBuffer) throws ZipException {
        checkInputBuffer(byteBuffer);
        int signature = byteBuffer.getInt();
        if (signature != SIGNATURE) {
            throw new ZipException("parse zip64 end of central directory error,"
                    + " signature is inconsistent with zip64 end of central directory signature.");
        }
        long recordSize = byteBuffer.getLong();
        if (recordSize < MIN_RECORD_SIZE) {
            throw new ZipException("parse zip64 end of central directory error,"
                    + " record size less than zip64 end of central directory record min size.");
        }
        return parseZip64Eocd(byteBuffer, recordSize);
    }

    private static Zip64Eocd parseZip64Eocd(ByteBuffer byteBuffer, long recordSize) {
        short versionMadeBy = byteBuffer.getShort();
        short versionNeeded = byteBuffer.getShort();
        int diskNumber = byteBuffer.getInt();
        int diskNumberOfCdStart = byteBuffer.getInt();
        long entriesOnDisk = byteBuffer.getLong();
        long totalEntries = byteBuffer.getLong();
        long centralDirectorySize = byteBuffer.getLong();
        long centralDirectoryOffset = byteBuffer.getLong();
        Zip64Eocd zip64Eocd = new Zip64Eocd();
        zip64Eocd.setRecordSize(recordSize);
        zip64Eocd.setVersionMadeBy(versionMadeBy);
        zip64Eocd.setVersionNeeded(versionNeeded);
        zip64Eocd.setDiskNumber(diskNumber);
        zip64Eocd.setDiskNumberOfCdStart(diskNumberOfCdStart);
        zip64Eocd.setEntriesOnDisk(entriesOnDisk);
        zip64Eocd.setTotalEntries(totalEntries);
        zip64Eocd.setCentralDirectorySize(centralDirectorySize);
        zip64Eocd.setCentralDirectoryOffset(centralDirectoryOffset);
        return zip64Eocd;
    }

    private static void checkInputBuffer(ByteBuffer buffer) throws ZipException {
        if (buffer == null) {
            throw new ZipException("parse zip64 end of central directory error,"
                    + " input buffer can not be null.");
        }
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new ZipException("parse zip64 end of central directory error,"
                    + " input buffer is not in little endian format.");
        }
        if (buffer.remaining() < MIN_SIZE) {
            throw new ZipException("parse zip64 end of central directory error,"
                    + " input buffer size less than zip64 end of central directory min size.");
        }
    }

    /**
     * Return byte array of zip64 end of central directory.
     *
     * @return byte array of zip64 end of central directory
     * @throws ZipException if transfer zip64 end of central directory failed
     */
    public byte[] toBytes() throws ZipException {
        long size = getSize();
        if (size > Integer.MAX_VALUE || size < MIN_SIZE) {
            throw new ZipException("zip64 eocd size out of rang: " + size);
        }
        long realRecordSize = size - RECORD_SIZE_END_OFFSET;
        ByteBuffer byteBuffer = ByteBuffer.allocate((int) size).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.putInt(SIGNATURE);
        byteBuffer.putLong(realRecordSize);
        byteBuffer.putShort(versionMadeBy);
        byteBuffer.putShort(versionNeeded);
        byteBuffer.putInt(diskNumber);
        byteBuffer.putInt(diskNumberOfCdStart);
        byteBuffer.putLong(entriesOnDisk);
        byteBuffer.putLong(totalEntries);
        byteBuffer.putLong(centralDirectorySize);
        byteBuffer.putLong(centralDirectoryOffset);
        if (hasZip64ExtensibleData()) {
            byteBuffer.put(zip64ExtensibleData);
        }
        return byteBuffer.array();
    }

    private boolean hasZip64ExtensibleData() {
        return zip64ExtensibleData != null && zip64ExtensibleData.length > 0;
    }

    /**
     * Return zip64 end of central directory size.
     *
     * @return zip64 end of central directory size
     */
    public long getSize() {
        long size = MIN_SIZE;
        if (hasZip64ExtensibleData()) {
            size += zip64ExtensibleData.length;
        }
        return size;
    }

    public long getRecordSize() {
        return recordSize;
    }

    public void setRecordSize(long recordSize) {
        this.recordSize = recordSize;
    }

    public short getVersionMadeBy() {
        return versionMadeBy;
    }

    public void setVersionMadeBy(short versionMadeBy) {
        this.versionMadeBy = versionMadeBy;
    }

    public short getVersionNeeded() {
        return versionNeeded;
    }

    public void setVersionNeeded(short versionNeeded) {
        this.versionNeeded = versionNeeded;
    }

    public int getDiskNumber() {
        return diskNumber;
    }

    public void setDiskNumber(int diskNumber) {
        this.diskNumber = diskNumber;
    }

    public int getDiskNumberOfCdStart() {
        return diskNumberOfCdStart;
    }

    public void setDiskNumberOfCdStart(int diskNumberOfCdStart) {
        this.diskNumberOfCdStart = diskNumberOfCdStart;
    }

    public long getEntriesOnDisk() {
        return entriesOnDisk;
    }

    public void setEntriesOnDisk(long entriesOnDisk) {
        this.entriesOnDisk = entriesOnDisk;
    }

    public long getTotalEntries() {
        return totalEntries;
    }

    public void setTotalEntries(long totalEntries) {
        this.totalEntries = totalEntries;
    }

    public long getCentralDirectorySize() {
        return centralDirectorySize;
    }

    public void setCentralDirectorySize(long centralDirectorySize) {
        this.centralDirectorySize = centralDirectorySize;
    }

    public long getCentralDirectoryOffset() {
        return centralDirectoryOffset;
    }

    public void setCentralDirectoryOffset(long centralDirectoryOffset) {
        this.centralDirectoryOffset = centralDirectoryOffset;
    }

    public void setZip64ExtensibleData(byte[] zip64ExtensibleData) {
        if (zip64ExtensibleData != null) {
            this.zip64ExtensibleData = zip64ExtensibleData.clone();
            return;
        }
        this.zip64ExtensibleData = null;
    }
}
