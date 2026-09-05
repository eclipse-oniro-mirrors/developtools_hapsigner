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
 * Zip64 extended information structure without tag and size.
 * uncompressed size                         8 bytes
 * compressed size                           4 bytes
 * relative offset of local header record    8 bytes
 * disk start number                         4 bytes
 *
 * @since 2026-08-10
 */
public class Zip64ExtendedInfo {
    /**
     * Header id for zip64 extended information extra field.
     */
    public static final short HEADER_ID = 0x0001;
    private static final int MIN_SIZE = 4;

    private Long uncompressedSize;
    private Long compressedSize;
    private Long localHeaderOffset;
    private Long diskStartNumber;

    /**
     * Parse zip64 extended information from the specific byte buffer.
     *
     * @param byteBuffer the specific byte buffer
     * @param needUncompressedSize whether needed uncompressed size
     * @param needCompressedSize whether needed compressed size
     * @param needLocalHeaderOffset whether needed local header offset
     * @param needDiskStartNumber whether needed disk start number
     * @return zip64 extended information
     * @throws ZipException if parsing zip64 extended information error
     */
    public static Zip64ExtendedInfo parse(ByteBuffer byteBuffer,
                                          boolean needUncompressedSize,
                                          boolean needCompressedSize,
                                          boolean needLocalHeaderOffset,
                                          boolean needDiskStartNumber) throws ZipException {
        checkInputBuffer(byteBuffer);
        Zip64ExtendedInfo zip64ExtendedInfo = new Zip64ExtendedInfo();
        if (needUncompressedSize) {
            checkRemaining(byteBuffer, Long.BYTES);
            zip64ExtendedInfo.setUncompressedSize(byteBuffer.getLong());
        }
        if (needCompressedSize) {
            checkRemaining(byteBuffer, Long.BYTES);
            zip64ExtendedInfo.setCompressedSize(byteBuffer.getLong());
        }
        if (needLocalHeaderOffset) {
            checkRemaining(byteBuffer, Long.BYTES);
            zip64ExtendedInfo.setLocalHeaderOffset(byteBuffer.getLong());
        }
        if (needDiskStartNumber) {
            checkRemaining(byteBuffer, Integer.BYTES);
            zip64ExtendedInfo.setDiskStartNumber(UnsignedDecimalUtil.getUnsignedInt(byteBuffer));
        }
        return zip64ExtendedInfo;
    }

    private static void checkRemaining(ByteBuffer buffer, int limit) throws ZipException {
        if (buffer.remaining() < limit) {
            throw new ZipException("invalid zip64 extend data size");
        }
    }

    private static void checkInputBuffer(ByteBuffer buffer) throws ZipException {
        if (buffer == null) {
            throw new ZipException("parse zip64 extended information error,"
                    + " input buffer can not be null.");
        }
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new ZipException("parse zip64 extended information error,"
                    + " input buffer is not in little endian format.");
        }
    }

    /**
     * Return byte array of zip64 extended information.
     *
     * @return byte array of zip64 extended information
     */
    public byte[] toBytes() {
        int dataSize = getDataSize();
        ByteBuffer byteBuffer = ByteBuffer.allocate(dataSize + MIN_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.putShort(HEADER_ID);
        UnsignedDecimalUtil.setUnsignedShort(byteBuffer, dataSize);
        if (uncompressedSize != null) {
            byteBuffer.putLong(uncompressedSize);
        }
        if (compressedSize != null) {
            byteBuffer.putLong(compressedSize);
        }
        if (localHeaderOffset != null) {
            byteBuffer.putLong(localHeaderOffset);
        }
        if (diskStartNumber != null) {
            UnsignedDecimalUtil.setUnsignedInt(byteBuffer, diskStartNumber);
        }
        return byteBuffer.array();
    }

    private int getDataSize() {
        int size = 0;
        if (uncompressedSize != null) {
            size += Long.BYTES;
        }
        if (compressedSize != null) {
            size += Long.BYTES;
        }
        if (localHeaderOffset != null) {
            size += Long.BYTES;
        }
        if (diskStartNumber != null) {
            size += Integer.BYTES;
        }
        return size;
    }

    public Long getUncompressedSize() {
        return uncompressedSize;
    }

    public void setUncompressedSize(Long uncompressedSize) {
        this.uncompressedSize = uncompressedSize;
    }

    public Long getCompressedSize() {
        return compressedSize;
    }

    public void setCompressedSize(Long compressedSize) {
        this.compressedSize = compressedSize;
    }

    public Long getLocalHeaderOffset() {
        return localHeaderOffset;
    }

    public void setLocalHeaderOffset(Long localHeaderOffset) {
        this.localHeaderOffset = localHeaderOffset;
    }

    public Long getDiskStartNumber() {
        return diskStartNumber;
    }

    public void setDiskStartNumber(Long diskStartNumber) {
        this.diskStartNumber = diskStartNumber;
    }
}
