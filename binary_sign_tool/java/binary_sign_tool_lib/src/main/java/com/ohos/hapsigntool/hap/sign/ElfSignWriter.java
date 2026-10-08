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

import com.ohos.elfio.ElfTypes;
import com.ohos.elfio.ElfioUtils;
import com.ohos.hapsigntool.entity.ElfSignConstants;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;

/**
 * Writes a signed ELF file by directly manipulating file bytes, replacing
 * elfio.save. Preserves all non-signature section data and positions,
 * appending new content (new .shstrtab + signature sections + new SHT)
 * at the end, then patching the ELF header in-place.
 *
 * <p>Each method has at most 5 parameters and 50 lines per the design.
 *
 * @since 2026/07/20
 */
public class ElfSignWriter {
    /**
     * Byte alignment of the section header table offset ({@code e_shoff})
     * for a 32-bit ELF, equal to {@code sizeof(Elf32_Addr)}.
     */
    private static final long SECTION_HEADER_TABLE_ALIGN_32 = 4L;

    /**
     * Byte alignment of the section header table offset ({@code e_shoff})
     * for a 64-bit ELF, equal to {@code sizeof(Elf64_Addr)}.
     */
    private static final long SECTION_HEADER_TABLE_ALIGN_64 = 8L;

    private ElfSignContext ctx;

    private long newShoff;

    private long codesignOffset;

    /**
     * Inject the signing context.
     *
     * @param ctx signing context
     */
    public void setCtx(ElfSignContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Write the signed ELF file.
     *
     * @param originalFile original (unsigned or previously signed) ELF file
     * @param outputFile destination file to write
     * @return offset of the .codesign section in the output file
     * @throws IOException if writing fails
     */
    public long write(File originalFile, File outputFile) throws IOException {
        long truncateOffset = ctx.getTruncateOffset();
        try (FileChannel src = FileChannel.open(originalFile.toPath(), StandardOpenOption.READ);
            FileChannel dest = FileChannel.open(outputFile.toPath(), StandardOpenOption.WRITE,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            copyOriginal(src, dest, truncateOffset);
            long pos = writeNewSections(dest, truncateOffset);
            writeSectionHeaderTable(dest, pos);
            writeElfHeader(dest);
        }
        return codesignOffset;
    }

    private void copyOriginal(FileChannel src, FileChannel dest, long len) throws IOException {
        long transferred = 0L;
        while (transferred < len) {
            long count = Math.min(len - transferred, Integer.MAX_VALUE);
            long n = src.transferTo(transferred, count, dest);
            if (n <= 0) {
                throw new IOException("Failed to transfer data at position " + transferred);
            }
            transferred += n;
        }
    }

    private long writeNewSections(FileChannel dest, long off) throws IOException {
        long pos = off;
        for (SectionInfo sec : ctx.getNewSections()) {
            if (!sec.isNew()) {
                continue;
            }
            pos = align(pos, sec.getAddrAlign());
            sec.setOffset(pos);
            if (ElfSignConstants.CODE_SIGN_SEC_NAME.equals(sec.getNameString())) {
                codesignOffset = sec.getOffset();
            }
            byte[] data = sec.getData();
            int writeLen = data != null ? data.length : (int) sec.getSize();
            if (data != null) {
                dest.position(pos);
                writeFully(dest, ByteBuffer.wrap(data));
            } else {
                dest.position(pos);
                writeFully(dest, ByteBuffer.wrap(new byte[writeLen]));
            }
            pos += sec.getSize();
        }
        return pos;
    }

    private long writeSectionHeaderTable(FileChannel dest, long pos) throws IOException {
        boolean is64 = ctx.getHeaderInfo().getFileClass() == ElfTypes.ELFCLASS64;
        long shoffAlign = is64 ? SECTION_HEADER_TABLE_ALIGN_64 : SECTION_HEADER_TABLE_ALIGN_32;
        newShoff = align(pos, shoffAlign);
        int entrySize = ctx.getHeaderInfo().getSectionEntrySize();
        ByteOrder byteOrder = getByteOrder();
        for (int i = 0; i < ctx.getNewSections().size(); i++) {
            SectionInfo sec = ctx.getNewSections().get(i);
            long entryPos = newShoff + (long) i * entrySize;
            ByteBuffer buf = sec.toByteBuffer(is64, byteOrder, entrySize);
            dest.position(entryPos);
            writeFully(dest, buf);
        }
        return newShoff;
    }

    private void writeElfHeader(FileChannel dest) throws IOException {
        boolean is64 = ctx.getHeaderInfo().getFileClass() == ElfTypes.ELFCLASS64;
        ByteBuffer buf = ByteBuffer.allocate(8).order(getByteOrder());
        buf.rewind();
        if (is64) {
            buf.putLong(newShoff);
        } else {
            buf.putInt((int) newShoff);
        }
        buf.flip();
        int shoffPos = is64 ? 0x28 : 0x20;
        dest.position(shoffPos);
        writeFully(dest, buf);

        int shnumPos = is64 ? 0x3C : 0x30;
        int newShnum = ctx.getNewSections().size();
        buf.rewind();
        buf.putShort((short) newShnum).flip();
        dest.position(shnumPos);
        writeFully(dest, buf);

        int shstrndxPos = is64 ? 0x3E : 0x32;
        short newShstrndx = ctx.getNewShStrTabIndex();
        buf.rewind();
        buf.putShort(newShstrndx).flip();
        dest.position(shstrndxPos);
        writeFully(dest, buf);
    }

    private void writeFully(FileChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int n = ch.write(buf);
            if (n <= 0) {
                throw new IOException("Failed to write data: channel returned " + n + " bytes");
            }
        }
    }

    private ByteOrder getByteOrder() {
        ElfioUtils.EndiannessConvertor convertor = new ElfioUtils.EndiannessConvertor();
        convertor.setup(ctx.getHeaderInfo().getEncoding());
        return convertor.getByteOrder();
    }

    private long align(long pos, long align) {
        if (align <= 0) {
            return pos;
        }
        long remainder = pos % align;
        if (remainder == 0) {
            return pos;
        }
        return pos + (align - remainder);
    }
}
