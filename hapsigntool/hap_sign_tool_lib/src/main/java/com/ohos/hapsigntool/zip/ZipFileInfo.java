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

import com.ohos.hapsigntool.error.ZipException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Information of ZIP file
 *
 * @since 2021/12/20
 */
public class ZipFileInfo {
    private final int centralDirectorySize;
    private final int centralDirectoryEntryCount;
    private long eocdOffset;
    private final EndOfCentralDirectory endOfCentralDirectory;
    private long centralDirectoryOffset;
    private Zip64Eocd zip64Eocd;
    private Zip64EocdLocator zip64EocdLocator;
    private boolean isZip64;

    public ZipFileInfo(long centralDirectoryOffset, int centralDirectorySize, int centralDirectoryEntryCount,
        long eocdOffset, EndOfCentralDirectory endOfCentralDirectory) {
        this.centralDirectoryOffset = centralDirectoryOffset;
        this.centralDirectorySize = centralDirectorySize;
        this.centralDirectoryEntryCount = centralDirectoryEntryCount;
        this.eocdOffset = eocdOffset;
        this.endOfCentralDirectory = endOfCentralDirectory;
    }

    /**
     * Return content buffer after zip central directory, include eocd/zip64 eocd/zip64 eocd locator.
     *
     * @return content buffer after zip central directory
     * @throws ZipException if transfer to buffer error
     */
    public ByteBuffer generateEocdBuffer() throws ZipException {
        if (!isZip64) {
            return getEocd();
        }
        byte[] zip64EocdBytes = zip64Eocd.toBytes();
        byte[] zip64EocdLocatorBytes = zip64EocdLocator.toBytes();
        byte[] eocdBytes = endOfCentralDirectory.toBytes();
        int capacity = zip64EocdBytes.length + zip64EocdLocatorBytes.length + eocdBytes.length;
        ByteBuffer byteBuffer = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.put(zip64EocdBytes);
        byteBuffer.put(zip64EocdLocatorBytes);
        byteBuffer.put(eocdBytes);
        byteBuffer.flip();
        return byteBuffer;
    }

    /**
     * Transfer to zip64 format
     */
    public void toZip64() {
        if (isZip64) {
            return;
        }
        zip64Eocd = createZip64EocdByEocd();
        zip64EocdLocator = createZip64EocdLocatorByEocd();
        isZip64 = true;
        endOfCentralDirectory.toZip64Format();
    }

    private Zip64Eocd createZip64EocdByEocd() {
        Zip64Eocd newZip64Eocd = new Zip64Eocd();
        newZip64Eocd.setRecordSize(Zip64Eocd.MIN_RECORD_SIZE);
        newZip64Eocd.setVersionNeeded((short) 45);
        newZip64Eocd.setVersionMadeBy((short) 45);
        newZip64Eocd.setDiskNumber(endOfCentralDirectory.getDiskNum());
        newZip64Eocd.setDiskNumberOfCdStart(endOfCentralDirectory.getcDStartDiskNum());
        newZip64Eocd.setEntriesOnDisk(endOfCentralDirectory.getThisDiskCDNum());
        newZip64Eocd.setTotalEntries(endOfCentralDirectory.getCDTotal());
        newZip64Eocd.setCentralDirectorySize(centralDirectorySize);
        newZip64Eocd.setCentralDirectoryOffset(centralDirectoryOffset);
        return newZip64Eocd;
    }

    private Zip64EocdLocator createZip64EocdLocatorByEocd() {
        Zip64EocdLocator newZip64EocdLocator = new Zip64EocdLocator();
        newZip64EocdLocator.setDiskNumberOfZip64Eocd(endOfCentralDirectory.getcDStartDiskNum());
        newZip64EocdLocator.setZip64EocdOffset(centralDirectoryOffset + centralDirectorySize);
        newZip64EocdLocator.setTotalNumberOfDisk(endOfCentralDirectory.getDiskNum());
        return newZip64EocdLocator;
    }

    /**
     * Update central directory offset.
     *
     * @param newOffset new central directory offset
     */
    public void updateCentralDirectoryOffset(long newOffset) {
        this.centralDirectoryOffset = newOffset;
        this.eocdOffset = newOffset + centralDirectorySize;
        if (isZip64) {
            zip64Eocd.setCentralDirectoryOffset(newOffset);
            zip64EocdLocator.setZip64EocdOffset(newOffset + centralDirectorySize);
            this.eocdOffset += zip64Eocd.getSize();
            this.eocdOffset += Zip64EocdLocator.SIZE;
            return;
        }
        endOfCentralDirectory.setOffset(newOffset);
    }

    public long getCentralDirectoryOffset() {
        return centralDirectoryOffset;
    }

    public int getCentralDirectorySize() {
        return centralDirectorySize;
    }

    public int getCentralDirectoryEntryCount() {
        return centralDirectoryEntryCount;
    }

    public long getEocdOffset() {
        return eocdOffset;
    }

    /**
     * Return end of central directory buffer.
     *
     * @return end of central directory buffer
     */
    public ByteBuffer getEocd() {
        byte[] bytes = endOfCentralDirectory.toBytes();
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    public void setZip64EocdLocator(Zip64EocdLocator zip64EocdLocator) {
        this.zip64EocdLocator = zip64EocdLocator;
    }

    public Zip64EocdLocator getZip64EocdLocator() {
        return zip64EocdLocator;
    }

    public void setZip64Eocd(Zip64Eocd zip64Eocd) {
        this.zip64Eocd = zip64Eocd;
    }

    public Zip64Eocd getZip64Eocd() {
        return zip64Eocd;
    }

    public void setZip64(boolean zip64) {
        isZip64 = zip64;
    }

    public boolean isZip64() {
        return isZip64;
    }
}