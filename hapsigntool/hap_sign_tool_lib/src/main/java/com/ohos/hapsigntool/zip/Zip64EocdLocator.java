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
 * Zip64 end of central directory locator.
 * zip64 end of central dir locator signature                 4 bytes (0x07064b50)
 * disk number where zip64 end of central directory starts    4 bytes
 * relative offset of zip64 end of central directory          8 bytes
 * total number of disks                                      4 bytes
 *
 * @since 2026-08-10
 */
public class Zip64EocdLocator {
    /**
     * zip64 end of central directory locator size.
     */
    public static final int SIZE = 20;

    /**
     * zip64 end of central directory locator signature.
     */
    public static final int SIGNATURE = 0x07064b50;

    private int diskNumberOfZip64Eocd;
    private long zip64EocdOffset;
    private int totalNumberOfDisk;

    /**
     * Parse zip64 end of central directory locator from the specific byte buffer.
     *
     * @param buffer the specific byte buffer
     * @return zip64 end of central directory locator
     * @throws ZipException if parsing zip64 end of central directory locator error
     */
    public static Zip64EocdLocator parse(ByteBuffer buffer) throws ZipException {
        checkInputBuffer(buffer);
        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new ZipException("parse zip64 end of central directory locator error,"
                    + " signature is inconsistent with zip64 end of central directory locator signature.");
        }
        int diskNumberOfZip64Eocd = buffer.getInt();
        long zip64EocdOffset = buffer.getLong();
        int totalNumberOfDisk = buffer.getInt();
        Zip64EocdLocator zip64EocdLocator = new Zip64EocdLocator();
        zip64EocdLocator.setDiskNumberOfZip64Eocd(diskNumberOfZip64Eocd);
        zip64EocdLocator.setZip64EocdOffset(zip64EocdOffset);
        zip64EocdLocator.setTotalNumberOfDisk(totalNumberOfDisk);
        return zip64EocdLocator;
    }

    private static void checkInputBuffer(ByteBuffer buffer) throws ZipException {
        if (buffer == null) {
            throw new ZipException("parse zip64 end of central directory locator error,"
                    + " input buffer can not be null.");
        }
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new ZipException("parse zip64 end of central directory locator error,"
                    + " input buffer is not in little endian format.");
        }
        if (buffer.remaining() < SIZE) {
            throw new ZipException("parse zip64 end of central directory locator error,"
                    + " input buffer size less than " + SIZE + ".");
        }
    }

    /**
     * Return byte array of zip64 end of central directory locator.
     *
     * @return byte array of zip64 end of central directory locator
     */
    public byte[] toBytes() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.putInt(SIGNATURE);
        byteBuffer.putInt(diskNumberOfZip64Eocd);
        byteBuffer.putLong(zip64EocdOffset);
        byteBuffer.putInt(totalNumberOfDisk);
        return byteBuffer.array();
    }

    public int getDiskNumberOfZip64Eocd() {
        return diskNumberOfZip64Eocd;
    }

    public void setDiskNumberOfZip64Eocd(int diskNumberOfZip64Eocd) {
        this.diskNumberOfZip64Eocd = diskNumberOfZip64Eocd;
    }

    public long getZip64EocdOffset() {
        return zip64EocdOffset;
    }

    public void setZip64EocdOffset(long zip64EocdOffset) {
        this.zip64EocdOffset = zip64EocdOffset;
    }

    public int getTotalNumberOfDisk() {
        return totalNumberOfDisk;
    }

    public void setTotalNumberOfDisk(int totalNumberOfDisk) {
        this.totalNumberOfDisk = totalNumberOfDisk;
    }
}
