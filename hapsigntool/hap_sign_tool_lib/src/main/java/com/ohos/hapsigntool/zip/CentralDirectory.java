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

package com.ohos.hapsigntool.zip;

import com.ohos.hapsigntool.error.ZipException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * resolve zip CentralDirectory data
 * CentralDirectory format for:
 * central file header signature   4 bytes  (0x02014b50)
 * version made by                 2 bytes
 * version needed to extract       2 bytes
 * general purpose bit flag        2 bytes
 * compression method              2 bytes
 * last mod file time              2 bytes
 * last mod file date              2 bytes
 * crc-32                          4 bytes
 * compressed size                 4 bytes
 * uncompressed size               4 bytes
 * file name length                2 bytes
 * extra field length              2 bytes
 * file comment length             2 bytes
 * disk number start               2 bytes
 * internal file attributes        2 bytes
 * external file attributes        4 bytes
 * relative offset of local header 4 bytes
 * file name (variable size)
 * extra field (variable size)
 * file comment (variable size)
 *
 * @since 2023/12/02
 */
public class CentralDirectory {
    /**
     * central directory invariable bytes length
     */
    public static final int CD_LENGTH = 46;

    /**
     * 4 bytes , central directory signature
     */
    public static final int SIGNATURE = 0x02014b50;

    /**
     * 2 bytes
     */
    private short version;

    /**
     * 2 bytes
     */
    private short versionExtra;

    /**
     * 2 bytes
     */
    private short flag;

    /**
     * 2 bytes
     */
    private short method;

    /**
     * 2 bytes
     */
    private short lastTime;

    /**
     * 2 bytes
     */
    private short lastDate;

    /**
     * 4 bytes
     */
    private int crc32;

    /**
     * 4 bytes
     */
    private long compressedSize;

    /**
     * 4 bytes
     */
    private long unCompressedSize;

    /**
     * 2 bytes
     */
    private int fileNameLength;

    /**
     * 2 bytes
     */
    private int extraLength;

    /**
     * 2 bytes
     */
    private int commentLength;

    /**
     * 2 bytes
     */
    private int diskNumStart;

    /**
     * 2 bytes
     */
    private short internalFile;

    /**
     * 4 bytes
     */
    private int externalFile;

    /**
     * 4 bytes
     */
    private long offset;

    /**
     * n bytes
     */
    private String fileName;

    /**
     * n bytes
     */
    private byte[] extraData;

    /**
     * n bytes
     */
    private byte[] comment;

    private int length;

    private Zip64ExtendedInfo zip64ExtendedInfo;

    private int zip64InfoOffsetInExtra = -1;
    private int zip64InfoLengthInExtra = 0;

    /**
     * updateLength
     */
    public void updateLength() {
        length = CD_LENGTH + fileNameLength + extraLength + commentLength;
    }

    /**
     * get Central Directory
     *
     * @param bf ByteBuffer
     * @return CentralDirectory
     * @throws ZipException read Central Directory exception
     */
    public static CentralDirectory getCentralDirectory(ByteBuffer bf) throws ZipException {
        CentralDirectory cd = new CentralDirectory();
        if (bf.getInt() != SIGNATURE) {
            throw new ZipException("find zip central directory failed");
        }

        cd.setVersion(bf.getShort());
        cd.setVersionExtra(bf.getShort());
        cd.setFlag(bf.getShort());
        cd.setMethod(bf.getShort());
        cd.setLastTime(bf.getShort());
        cd.setLastDate(bf.getShort());
        cd.setCrc32(bf.getInt());
        cd.setCompressedSize(UnsignedDecimalUtil.getUnsignedInt(bf));
        cd.setUnCompressedSize(UnsignedDecimalUtil.getUnsignedInt(bf));
        cd.setFileNameLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setExtraLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setCommentLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setDiskNumStart(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setInternalFile(bf.getShort());
        cd.setExternalFile(bf.getInt());
        cd.setOffset(UnsignedDecimalUtil.getUnsignedInt(bf));
        if (cd.getFileNameLength() > 0) {
            byte[] readFileName = new byte[cd.getFileNameLength()];
            bf.get(readFileName);
            cd.setFileName(new String(readFileName, StandardCharsets.UTF_8));
        }
        if (cd.getExtraLength() > 0) {
            byte[] extra = new byte[cd.getExtraLength()];
            bf.get(extra);
            cd.setExtraData(extra);
        }
        if (cd.getCommentLength() > 0) {
            byte[] readComment = new byte[cd.getCommentLength()];
            bf.get(readComment);
            cd.setComment(readComment);
        }
        cd.updateLength();
        parseZip64ExtendInfoIfNeeded(cd);
        return cd;
    }

    private static void parseZip64ExtendInfoIfNeeded(CentralDirectory centralDirectory) throws ZipException {
        if (centralDirectory.needZip64ExtendInfo()) {
            // need zip64 extend info
            int extraLength = centralDirectory.getExtraLength();
            if (extraLength < Integer.BYTES) {
                throw new ZipException("parse zip central directory failed, invalid extra length.");
            }
            // parse zip64 extend info from extra data
            byte[] extraBytes = centralDirectory.getExtraData();
            if (extraBytes == null || extraBytes.length != extraLength) {
                throw new ZipException("parse zip central directory failed, invalid extra data.");
            }
            ByteBuffer extraBuffer = ByteBuffer.wrap(extraBytes).order(ByteOrder.LITTLE_ENDIAN);
            Zip64ExtendedInfo zip64ExtendedInfo = null;
            int readOffset = 0;
            while (extraBuffer.remaining() >= Integer.BYTES) {
                short headerId = extraBuffer.getShort();
                int dataSize = UnsignedDecimalUtil.getUnsignedShort(extraBuffer);
                readOffset += Integer.BYTES;
                if (headerId == 0 && dataSize == 0) {
                    // maybe alignment bytes
                    break;
                }
                if (dataSize > extraBuffer.remaining()) {
                    throw new ZipException("parse zip central directory failed, invalid extra data size.");
                }
                if (headerId != Zip64ExtendedInfo.HEADER_ID) {
                    extraBuffer.position(extraBuffer.position() + dataSize);
                    readOffset += dataSize;
                    continue;
                }
                extraBuffer.limit(extraBuffer.position() + dataSize);
                zip64ExtendedInfo = Zip64ExtendedInfo.parse(extraBuffer, centralDirectory.needZip64UncompressedSize(),
                        centralDirectory.needZip64CompressedSize(), centralDirectory.needZip64LocalHeaderOffset(),
                        centralDirectory.needZip64DiskNumStart());
                centralDirectory.setZip64ExtendedInfo(zip64ExtendedInfo);
                centralDirectory.setZip64InfoOffsetInExtra(readOffset - Integer.BYTES);
                centralDirectory.setZip64InfoLengthInExtra(dataSize + Integer.BYTES);
                break;
            }
            if (zip64ExtendedInfo == null) {
                throw new ZipException("zip64 extend info is required, but not found.");
            }
        }
    }

    private boolean needZip64ExtendInfo() {
        return needZip64UncompressedSize()
                || needZip64CompressedSize()
                || needZip64LocalHeaderOffset()
                || needZip64DiskNumStart();
    }

    private boolean needZip64UncompressedSize() {
        return this.unCompressedSize == UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE;
    }

    private boolean needZip64CompressedSize() {
        return this.compressedSize == UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE;
    }

    private boolean needZip64LocalHeaderOffset() {
        return this.offset == UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE;
    }

    private boolean needZip64DiskNumStart() {
        return this.diskNumStart == UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE;
    }

    /**
     * Update local file header offset.
     *
     * @param newOffset new local file header offset
     * @throws ZipException if update local file header offset failed
     */
    public void updateOffset(long newOffset) throws ZipException {
        long preOffset = getOffset();
        if (newOffset == preOffset) {
            return;
        }
        this.offset = Math.min(newOffset, UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE);
        if (zip64ExtendedInfo != null) {
            zip64ExtendedInfo.setLocalHeaderOffset(newOffset);
            byte[] newZip64ExtendedInfoBytes = zip64ExtendedInfo.toBytes();
            int newExtraLength = extraData.length + newZip64ExtendedInfoBytes.length - zip64InfoLengthInExtra;
            if (newExtraLength < 0 || newExtraLength < newZip64ExtendedInfoBytes.length) {
                throw new ZipException("invalid extra data length during zip64 offset update");
            }
            byte[] newExtraData = new byte[newExtraLength];
            System.arraycopy(newZip64ExtendedInfoBytes, 0, newExtraData, 0, newZip64ExtendedInfoBytes.length);
            System.arraycopy(extraData, 0, newExtraData, newZip64ExtendedInfoBytes.length, zip64InfoOffsetInExtra);
            System.arraycopy(extraData, zip64InfoOffsetInExtra + zip64InfoLengthInExtra, newExtraData,
                    newZip64ExtendedInfoBytes.length + zip64InfoOffsetInExtra,
                    extraData.length - (zip64InfoOffsetInExtra + zip64InfoLengthInExtra));
            extraData = newExtraData;
            extraLength = newExtraData.length;
            zip64InfoOffsetInExtra = 0;
            zip64InfoLengthInExtra = newZip64ExtendedInfoBytes.length;
            updateLength();
            return;
        }
        if (newOffset >= UnsignedDecimalUtil.MAX_UNSIGNED_INT_VALUE) {
            // need add zip64 extend info to extra data
            zip64ExtendedInfo = new Zip64ExtendedInfo();
            zip64ExtendedInfo.setLocalHeaderOffset(newOffset);
            byte[] zip64ExtendedInfoBytes = zip64ExtendedInfo.toBytes();
            if (extraData == null || extraData.length == 0) {
                extraData = zip64ExtendedInfoBytes;
                extraLength = zip64ExtendedInfoBytes.length;
            } else {
                int newExtraLength = extraData.length + zip64ExtendedInfoBytes.length;
                if (newExtraLength > UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE) {
                    throw new ZipException("zip extra length out of range");
                }
                byte[] newExtraData = new byte[newExtraLength];
                System.arraycopy(zip64ExtendedInfoBytes, 0, newExtraData, 0, zip64ExtendedInfoBytes.length);
                System.arraycopy(extraData, 0, newExtraData, zip64ExtendedInfoBytes.length, extraData.length);
                extraData = newExtraData;
                extraLength = newExtraData.length;
            }
            zip64InfoOffsetInExtra = 0;
            zip64InfoLengthInExtra = zip64ExtendedInfoBytes.length;
            updateLength();
        }
    }

    /**
     * change Central Directory to bytes
     *
     * @return bytes
     */
    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(SIGNATURE);
        UnsignedDecimalUtil.setUnsignedShort(bf, version);
        UnsignedDecimalUtil.setUnsignedShort(bf, versionExtra);
        UnsignedDecimalUtil.setUnsignedShort(bf, flag);
        UnsignedDecimalUtil.setUnsignedShort(bf, method);
        UnsignedDecimalUtil.setUnsignedShort(bf, lastTime);
        UnsignedDecimalUtil.setUnsignedShort(bf, lastDate);
        UnsignedDecimalUtil.setUnsignedInt(bf, crc32);
        UnsignedDecimalUtil.setUnsignedInt(bf, compressedSize);
        UnsignedDecimalUtil.setUnsignedInt(bf, unCompressedSize);
        UnsignedDecimalUtil.setUnsignedShort(bf, fileNameLength);
        UnsignedDecimalUtil.setUnsignedShort(bf, extraLength);
        UnsignedDecimalUtil.setUnsignedShort(bf, commentLength);
        UnsignedDecimalUtil.setUnsignedShort(bf, diskNumStart);
        UnsignedDecimalUtil.setUnsignedShort(bf, internalFile);
        UnsignedDecimalUtil.setUnsignedInt(bf, externalFile);
        UnsignedDecimalUtil.setUnsignedInt(bf, offset);
        if (fileNameLength > 0) {
            bf.put(fileName.getBytes(StandardCharsets.UTF_8));
        }
        if (extraLength > 0) {
            bf.put(extraData);
        }
        if (commentLength > 0) {
            bf.put(comment);
        }
        return bf.array();
    }

    public short getVersion() {
        return version;
    }

    public void setVersion(short version) {
        this.version = version;
    }

    public short getVersionExtra() {
        return versionExtra;
    }

    public void setVersionExtra(short versionExtra) {
        this.versionExtra = versionExtra;
    }

    public short getFlag() {
        return flag;
    }

    public void setFlag(short flag) {
        this.flag = flag;
    }

    public short getMethod() {
        return method;
    }

    public void setMethod(short method) {
        this.method = method;
    }

    public short getLastTime() {
        return lastTime;
    }

    public void setLastTime(short lastTime) {
        this.lastTime = lastTime;
    }

    public short getLastDate() {
        return lastDate;
    }

    public void setLastDate(short lastDate) {
        this.lastDate = lastDate;
    }

    public int getCrc32() {
        return crc32;
    }

    public void setCrc32(int crc32) {
        this.crc32 = crc32;
    }

    public long getCompressedSize() {
        if (zip64ExtendedInfo != null && zip64ExtendedInfo.getCompressedSize() != null) {
            return zip64ExtendedInfo.getCompressedSize();
        }
        return compressedSize;
    }

    public void setCompressedSize(long compressedSize) {
        this.compressedSize = compressedSize;
    }

    public long getUnCompressedSize() {
        if (zip64ExtendedInfo != null && zip64ExtendedInfo.getUncompressedSize() != null) {
            return zip64ExtendedInfo.getUncompressedSize();
        }
        return unCompressedSize;
    }

    public void setUnCompressedSize(long unCompressedSize) {
        this.unCompressedSize = unCompressedSize;
    }

    public int getFileNameLength() {
        return fileNameLength;
    }

    public void setFileNameLength(int fileNameLength) {
        this.fileNameLength = fileNameLength;
    }

    public int getExtraLength() {
        return extraLength;
    }

    public void setExtraLength(int extraLength) {
        this.extraLength = extraLength;
    }

    public int getCommentLength() {
        return commentLength;
    }

    public void setCommentLength(int commentLength) {
        this.commentLength = commentLength;
    }

    public int getDiskNumStart() {
        return diskNumStart;
    }

    public void setDiskNumStart(int diskNumStart) {
        this.diskNumStart = diskNumStart;
    }

    public short getInternalFile() {
        return internalFile;
    }

    public void setInternalFile(short internalFile) {
        this.internalFile = internalFile;
    }

    public int getExternalFile() {
        return externalFile;
    }

    public void setExternalFile(int externalFile) {
        this.externalFile = externalFile;
    }

    public long getOffset() {
        if (zip64ExtendedInfo != null && zip64ExtendedInfo.getLocalHeaderOffset() != null) {
            return zip64ExtendedInfo.getLocalHeaderOffset();
        }
        return offset;
    }

    public void setOffset(long offset) {
        this.offset = offset;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public byte[] getExtraData() {
        return extraData;
    }

    public void setExtraData(byte[] extraData) {
        this.extraData = extraData;
    }

    public byte[] getComment() {
        return comment;
    }

    public void setComment(byte[] comment) {
        this.comment = comment;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public void setZip64ExtendedInfo(Zip64ExtendedInfo zip64ExtendedInfo) {
        this.zip64ExtendedInfo = zip64ExtendedInfo;
    }

    public void setZip64InfoLengthInExtra(int zip64InfoLengthInExtra) {
        this.zip64InfoLengthInExtra = zip64InfoLengthInExtra;
    }

    public void setZip64InfoOffsetInExtra(int zip64InfoOffsetInExtra) {
        this.zip64InfoOffsetInExtra = zip64InfoOffsetInExtra;
    }
}