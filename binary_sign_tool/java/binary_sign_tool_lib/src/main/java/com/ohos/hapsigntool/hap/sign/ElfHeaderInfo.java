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

package com.ohos.hapsigntool.hap.sign;

/**
 * Holds only the ELF header fields needed for in-place header patching
 * and SHT entry writing. All other header fields are preserved verbatim
 * by {@code copyOriginal} and need not be stored here.
 *
 * @since 2026/07/20
 */
public class ElfHeaderInfo {
    private byte fileClass;

    private byte encoding;

    private short sectionEntrySize;

    private short sectionNameStrIndex;

    private long shtOff;

    private short shNum;

    /**
     * Get ELF file class (ELFCLASS32 or ELFCLASS64).
     *
     * @return file class
     */
    public byte getFileClass() {
        return fileClass;
    }

    /**
     * Set ELF file class.
     *
     * @param fileClass file class
     */
    public void setFileClass(byte fileClass) {
        this.fileClass = fileClass;
    }

    /**
     * Get ELF data encoding (ELFDATA2LSB or ELFDATA2MSB).
     *
     * @return encoding
     */
    public byte getEncoding() {
        return encoding;
    }

    /**
     * Set ELF data encoding.
     *
     * @param encoding encoding
     */
    public void setEncoding(byte encoding) {
        this.encoding = encoding;
    }

    /**
     * Get original e_shentsize. Kept unchanged when writing the new SHT;
     * also used as the entry stride for writing SHT entries.
     *
     * @return section entry size
     */
    public short getSectionEntrySize() {
        return sectionEntrySize;
    }

    /**
     * Set original e_shentsize.
     *
     * @param sectionEntrySize section entry size
     */
    public void setSectionEntrySize(short sectionEntrySize) {
        this.sectionEntrySize = sectionEntrySize;
    }

    public long getShtOff() {
        return shtOff;
    }

    public void setShtOff(long shtOff) {
        this.shtOff = shtOff;
    }

    public short getSectionNameStrIndex() {
        return sectionNameStrIndex;
    }

    public void setSectionNameStrIndex(short sectionNameStrIndex) {
        this.sectionNameStrIndex = sectionNameStrIndex;
    }

    public short getShNum() {
        return shNum;
    }

    public void setShNum(short shNum) {
        this.shNum = shNum;
    }
}
