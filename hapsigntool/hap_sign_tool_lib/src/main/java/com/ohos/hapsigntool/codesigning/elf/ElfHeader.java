/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.codesigning.elf;

import com.ohos.hapsigntool.codesigning.exception.ElfFormatException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ELF header info
 *
 * @since 2024/07/01
 */
public class ElfHeader {
    /**
     * Magic number and other info
     */
    private byte[] ident = new byte[ElfDefine.EI_NIDENT_LEN];

    /**
     * 32-bit or 64-bit file
     */
    private byte eiClass;

    /**
     * LITTLE_ENDIAN or BIG_ENDIAN
     */
    private byte eiData;

    /**
     * elf version
     */
    private byte eiVersion;

    /**
     * Object file type
     */
    private short eType;

    /**
     * Architecture
     */
    private int eMachine;

    /**
     * Object file version
     */
    private int eVersion;

    /**
     * Entry point virtual address
     */
    private long eEntry;

    /**
     * Program header table file offset
     */
    private long ePhOff;

    /**
     * Section header table file offset
     */
    private long eShOff;

    /**
     * Processor-specific flags
     */
    private int eFlags;

    /**
     * ELF header size in bytes
     */
    private short eEhSize;

    /**
     * Program header table entry size
     */
    private short ePhEntSize;

    /**
     * Program header table entry count
     */
    private short ePhNum;

    /**
     * Section header table entry size
     */
    private short eShEntSize;

    /**
     * Section header table entry count
     */
    private short eShNum;

    /**
     * Section header string table index
     */
    private short eShStrndx;

    /**
     * Constructor for ElfHeader
     *
     * @param is InputStream
     * @throws IOException io error
     * @throws ElfFormatException elf file format error
     */
    public ElfHeader(InputStream is) throws IOException, ElfFormatException {
        int read = is.read(ident);
        if (read != ident.length || !isElfFile(ident)) {
            throw new ElfFormatException("Not a elf file");
        }
        eiClass = ident[4];
        eiData = ident[5];
        eiVersion = ident[6];
        if (eiVersion < 1) {
            throw new ElfFormatException("ELF eiVersion is incorrect");
        }
        int len;
        if (eiClass == ElfDefine.ELF_32_CLASS) {
            len = ElfDefine.ELF_HEADER_32_LEN - ElfDefine.EI_NIDENT_LEN;
        } else if (eiClass == ElfDefine.ELF_64_CLASS) {
            len = ElfDefine.ELF_HEADER_64_LEN - ElfDefine.EI_NIDENT_LEN;
        } else {
            throw new ElfFormatException("ELF eiClass is incorrect");
        }
        ByteOrder bo;
        if (eiData == ElfDefine.ELF_DATA_2_LSB) {
            bo = ByteOrder.LITTLE_ENDIAN;
        } else if (eiData == ElfDefine.ELF_DATA_2_MSB) {
            bo = ByteOrder.BIG_ENDIAN;
        } else {
            throw new ElfFormatException("ELF eiData is incorrect");
        }
        byte[] bytes = new byte[len];
        read = is.read(bytes);
        if (read != len) {
            throw new ElfFormatException("ELF file header is incorrect");
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        byteBuffer.order(bo);
        initHeader(byteBuffer);
    }

    private void initHeader(ByteBuffer byteBuffer) throws ElfFormatException {
        eType = byteBuffer.getShort();
        eMachine = byteBuffer.getShort();
        eVersion = byteBuffer.getInt();

        if (eiClass == ElfDefine.ELF_32_CLASS) {
            eEntry = byteBuffer.getInt() & 0xFFFFFFFFL;
            ePhOff = byteBuffer.getInt() & 0xFFFFFFFFL;
            eShOff = byteBuffer.getInt() & 0xFFFFFFFFL;
            if (ePhOff != ElfDefine.ELF_HEADER_32_LEN) {
                throw new ElfFormatException("ELF Program header table file offset is incorrect");
            }
        } else {
            eEntry = byteBuffer.getLong();
            ePhOff = byteBuffer.getLong();
            eShOff = byteBuffer.getLong();
            if (ePhOff != ElfDefine.ELF_HEADER_64_LEN) {
                throw new ElfFormatException("ELF Program header table file offset is incorrect");
            }
        }
        eFlags = byteBuffer.getInt();
        eEhSize = byteBuffer.getShort();
        ePhEntSize = byteBuffer.getShort();
        ePhNum = byteBuffer.getShort();
        eShEntSize = byteBuffer.getShort();
        eShNum = byteBuffer.getShort();
        eShStrndx = byteBuffer.getShort();
    }

    public byte getEiClass() {
        return eiClass;
    }

    public byte getEiData() {
        return eiData;
    }

    public long getEPhOff() {
        return ePhOff;
    }

    public short getEPhnum() {
        return ePhNum;
    }

    /**
     * elf file start with [0x7F 0x45 0x4C 0x46]
     *
     * @param bytes byte array
     * @return true if start with [0x7F 0x45 0x4C 0x46]
     */
    public static boolean isElfFile(byte[] bytes) {
        if (bytes == null || bytes.length < 4) {
            return false;
        }
        return bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46;
    }
}
