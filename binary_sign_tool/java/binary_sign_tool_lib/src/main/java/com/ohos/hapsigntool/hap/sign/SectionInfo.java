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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * POJO holding all fields of a single ELF section for use by ElfSignWriter.
 *
 * <p>Sections are split into two roles via {@link #isNew}:
 * <ul>
 *   <li>{@code isNew == false}: retained section whose data is block-copied from
 *       the original file. {@code data} is typically {@code null}.</li>
 *   <li>{@code isNew == true}: newly created section whose data must be written
 *       explicitly (e.g. {@code .codesign} 4K zero placeholder,
 *       {@code .profile}/{@code .permission} actual content).</li>
 * </ul>
 * Special case: {@code .shstrtab} is {@code isNew == false} but {@code data}
 * is non-null, storing the original {@code .shstrtab} bytes for
 * {@code buildNewShstrtab} to rebuild. Its offset/size are overridden in
 * {@code writeSectionHeaders} to the new values.
 *
 * @since 2026/07/20
 */
public class SectionInfo {
    private int index;

    private int nameOffset;

    private int type;

    private long flags;

    private long address;

    private long offset;

    private long size;

    private int link;

    private int info;

    private long addrAlign;

    private long entSize;

    private String nameString = "";

    private byte[] data;

    private boolean isNew;

    /**
     * Get section index.
     *
     * @return section index
     */
    public int getIndex() {
        return index;
    }

    /**
     * Set section index.
     *
     * @param index section index
     */
    public void setIndex(int index) {
        this.index = index;
    }

    /**
     * Get name string offset in .shstrtab (sh_name).
     *
     * @return name offset
     */
    public int getNameOffset() {
        return nameOffset;
    }

    /**
     * Set name string offset in .shstrtab.
     *
     * @param nameOffset name offset
     */
    public void setNameOffset(int nameOffset) {
        this.nameOffset = nameOffset;
    }

    /**
     * Get section type (sh_type).
     *
     * @return section type
     */
    public int getType() {
        return type;
    }

    /**
     * Set section type.
     *
     * @param type section type
     */
    public void setType(int type) {
        this.type = type;
    }

    /**
     * Get section flags (sh_flags).
     *
     * @return section flags
     */
    public long getFlags() {
        return flags;
    }

    /**
     * Set section flags.
     *
     * @param flags section flags
     */
    public void setFlags(long flags) {
        this.flags = flags;
    }

    /**
     * Get section virtual address (sh_addr).
     *
     * @return virtual address
     */
    public long getAddress() {
        return address;
    }

    /**
     * Set section virtual address.
     *
     * @param address virtual address
     */
    public void setAddress(long address) {
        this.address = address;
    }

    /**
     * Get section file offset (sh_offset).
     *
     * @return file offset
     */
    public long getOffset() {
        return offset;
    }

    /**
     * Set section file offset.
     *
     * @param offset file offset
     */
    public void setOffset(long offset) {
        this.offset = offset;
    }

    /**
     * Get section size (sh_size).
     *
     * @return section size
     */
    public long getSize() {
        return size;
    }

    /**
     * Set section size.
     *
     * @param size section size
     */
    public void setSize(long size) {
        this.size = size;
    }

    /**
     * Get section link (sh_link).
     *
     * @return link value
     */
    public int getLink() {
        return link;
    }

    /**
     * Set section link.
     *
     * @param link link value
     */
    public void setLink(int link) {
        this.link = link;
    }

    /**
     * Get section info (sh_info).
     *
     * @return info value
     */
    public int getInfo() {
        return info;
    }

    /**
     * Set section info.
     *
     * @param info info value
     */
    public void setInfo(int info) {
        this.info = info;
    }

    /**
     * Get section address alignment (sh_addralign).
     *
     * @return address alignment
     */
    public long getAddrAlign() {
        return addrAlign;
    }

    /**
     * Set section address alignment.
     *
     * @param addrAlign address alignment
     */
    public void setAddrAlign(long addrAlign) {
        this.addrAlign = addrAlign;
    }

    /**
     * Get section entry size (sh_entsize).
     *
     * @return entry size
     */
    public long getEntSize() {
        return entSize;
    }

    /**
     * Set section entry size.
     *
     * @param entSize entry size
     */
    public void setEntSize(long entSize) {
        this.entSize = entSize;
    }

    /**
     * Get resolved section name string.
     *
     * @return section name
     */
    public String getNameString() {
        return nameString;
    }

    /**
     * Set resolved section name string.
     *
     * @param nameString section name
     */
    public void setNameString(String nameString) {
        this.nameString = nameString;
    }

    /**
     * Get section data. Non-null for .shstrtab (original bytes) and new sections
     * (content to write). Null for retained sections (data block-copied).
     *
     * @return section data or null
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Set section data.
     *
     * @param data section data
     */
    public void setData(byte[] data) {
        this.data = data;
    }

    /**
     * Check if this is a newly created section.
     *
     * @return true if new section
     */
    public boolean isNew() {
        return isNew;
    }

    /**
     * Set whether this is a newly created section.
     *
     * @param isNew true if new section
     */
    public void setNew(boolean isNew) {
        this.isNew = isNew;
    }

    /**
     * Create a deep copy of this section info. The {@code data} byte array is
     * cloned so the copy is fully independent of the original.
     *
     * @return a deep copy of this SectionInfo
     */
    public SectionInfo deepCopy() {
        SectionInfo copy = new SectionInfo();
        copy.index = this.index;
        copy.nameOffset = this.nameOffset;
        copy.type = this.type;
        copy.flags = this.flags;
        copy.address = this.address;
        copy.offset = this.offset;
        copy.size = this.size;
        copy.link = this.link;
        copy.info = this.info;
        copy.addrAlign = this.addrAlign;
        copy.entSize = this.entSize;
        copy.nameString = this.nameString;
        copy.data = this.data == null ? null : Arrays.copyOf(this.data, data.length);
        copy.isNew = this.isNew;
        return copy;
    }

    /**
     * Serialize this section header into a ByteBuffer suitable for writing
     * to the section header table. The buffer is allocated, filled, and
     * flipped, ready for a single write call.
     *
     * @param is64 true for ELF64, false for ELF32
     * @param order byte order of the ELF file
     * @param entrySize section header entry size (e_shentsize)
     * @return a flipped ByteBuffer ready for channel write
     */
    public ByteBuffer toByteBuffer(boolean is64, ByteOrder order, int entrySize) {
        ByteBuffer buf = ByteBuffer.allocate(entrySize).order(order);
        buf.putInt(nameOffset);
        buf.putInt(type);
        if (is64) {
            buf.putLong(flags);
            buf.putLong(address);
            buf.putLong(offset);
            buf.putLong(size);
        } else {
            buf.putInt((int) flags);
            buf.putInt((int) address);
            buf.putInt((int) offset);
            buf.putInt((int) size);
        }
        buf.putInt(link);
        buf.putInt(info);
        if (is64) {
            buf.putLong(addrAlign);
            buf.putLong(entSize);
        } else {
            buf.putInt((int) addrAlign);
            buf.putInt((int) entSize);
        }
        buf.flip();
        return buf;
    }
}
