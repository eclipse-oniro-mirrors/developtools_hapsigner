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
import com.ohos.elfio.Elfio;
import com.ohos.elfio.Section;
import com.ohos.hapsigntool.codesigning.exception.ElfFormatException;
import com.ohos.hapsigntool.entity.ElfSignConstants;
import com.ohos.hapsigntool.utils.LogUtils;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Aggregates all inputs needed by {@link ElfSignWriter}. Loads an ELF file,
 * extracts header and section info, validates the layout, computes the
 * truncate offset, builds a new {@code .shstrtab} (preserving the original
 * one in place), appends signature sections, and appends a magic marker
 * to the new {@code .shstrtab} for re-sign identification.
 *
 * @since 2026/07/20
 */
public class ElfSignContext {
    private static final LogUtils LOGGER = new LogUtils(ElfSignContext.class);

    private ElfHeaderInfo headerInfo;

    private List<SectionInfo> origSections;

    private List<SectionInfo> newSections;

    private short newShStrTabIndex;

    private long truncateOffset;

    /**
     * Get the original section list extracted from the input ELF file. This
     * list is not modified by section rebuilding; use {@link #getNewSections()}
     * for the final output list.
     *
     * @return original section list in table order
     */
    public List<SectionInfo> getOrigSections() {
        return origSections;
    }

    /**
     * Get the final section list after backward-scan truncation, new
     * {@code .shstrtab} creation, and signature section appending. This is
     * the list that {@link ElfSignWriter} serializes to the output file.
     *
     * @return final section list in table order
     */
    public List<SectionInfo> getNewSections() {
        return newSections;
    }

    /**
     * Get ELF header info extracted from the input file. Used by
     * {@link ElfSignWriter} for in-place header patching and SHT writing.
     *
     * @return header info, or {@code null} if not yet loaded
     */
    public ElfHeaderInfo getHeaderInfo() {
        return headerInfo;
    }

    /**
     * Get the truncate offset computed by {@link #computeOffset}. The output
     * file copies all bytes from {@code [0, truncateOffset)} of the input.
     *
     * @return truncate offset in bytes
     */
    public long getTruncateOffset() {
        return truncateOffset;
    }

    /**
     * Get the index of the new {@code .shstrtab} within
     * {@link #getNewSections()}. This value is set by
     * {@link #buildNewShstrtab} and written to {@code e_shstrndx} by
     * {@link ElfSignWriter}.
     *
     * @return index of the new {@code .shstrtab}
     */
    public short getNewShStrTabIndex() {
        return newShStrTabIndex;
    }

    /**
     * Extract ELF header info from elfio and store it in this context.
     * Validates that e_shoff, e_shstrndx, and e_shnum are present
     * and not using extended numbering.
     *
     * @param elfio loaded ELF file reader
     * @return true if extraction succeeded; false if validation failed
     */
    public boolean extractHeaderInfo(Elfio elfio) {
        ElfHeaderInfo info = new ElfHeaderInfo();
        info.setFileClass(elfio.getElfClass());
        info.setEncoding(elfio.getEncoding());
        info.setSectionEntrySize(elfio.getSectionEntrySize());
        long shoff = elfio.getSectionsOffset();
        short shstrndx = elfio.getSectionNameStrIndex();
        short shnum = elfio.getHeader().getSectionNum();
        if (shoff == 0) {
            LOGGER.error("No section header table (e_shoff == 0)");
            return false;
        }
        if (shstrndx == ElfTypes.SHN_UNDEF) {
            LOGGER.error("No section name string table (e_shstrndx == SHN_UNDEF)");
            return false;
        }
        if (shnum == 0) {
            LOGGER.error("Extended section numbering not supported (e_shnum == 0)");
            return false;
        }
        if ((shstrndx & 0xFFFF) == ElfTypes.SHN_XINDEX) {
            LOGGER.error("Extended section name index not supported (e_shstrndx == SHN_XINDEX)");
            return false;
        }
        info.setShtOff(shoff);
        info.setSectionNameStrIndex(shstrndx);
        info.setShNum(shnum);
        this.headerInfo = info;
        return true;
    }

    /**
     * Extract all section headers from elfio into {@link #getOrigSections()}.
     * For every {@code .shstrtab} section, its string-table data is also
     * loaded so that {@link #isMagicShstrtab} can detect magic markers and
     * {@link #buildNewShstrtab} can operate on the raw bytes.
     *
     * @param elfio loaded ELF file reader
     * @throws IOException if reading section data fails
     */
    public void extractSectionInfos(Elfio elfio) throws IOException {
        List<SectionInfo> sections = new ArrayList<>();
        for (int i = 0; i < elfio.getSectionsCount(); i++) {
            Section sec = elfio.getSection(i);
            SectionInfo info = new SectionInfo();
            info.setIndex(i);
            info.setNameOffset(sec.getNameStringOffset());
            info.setType(sec.getType());
            info.setFlags(sec.getFlags());
            info.setAddress(sec.getAddress());
            info.setOffset(sec.getOffset());
            info.setSize(sec.getSize());
            info.setLink(sec.getLink());
            info.setInfo(sec.getInfo());
            info.setAddrAlign(sec.getAddrAlign());
            info.setEntSize(sec.getEntSize());
            info.setNameString(sec.getName());
            info.setNew(false);
            if (ElfSignConstants.SHSTRTAB_SEC_NAME.equals(sec.getName())) {
                info.setData(sec.getData());
            }
            sections.add(info);
        }
        this.origSections = sections;
    }

    /**
     * Check if a section is a self-created {@code .shstrtab} by verifying
     * its name is {@code ".shstrtab"} and its data ends with the
     * {@link ElfSignConstants#SHSTRTAB_MAGIC} marker.
     *
     * @param sec section info to check
     * @return true if this is a magic-marked .shstrtab from a previous sign
     */
    public boolean isMagicShstrtab(SectionInfo sec) {
        if (sec == null || !ElfSignConstants.SHSTRTAB_SEC_NAME.equals(sec.getNameString())) {
            return false;
        }
        byte[] data = sec.getData();
        if (data == null || data.length < ElfSignConstants.SHSTRTAB_MAGIC.length) {
            return false;
        }
        int start = data.length - ElfSignConstants.SHSTRTAB_MAGIC.length;
        for (int i = 0; i < ElfSignConstants.SHSTRTAB_MAGIC.length; i++) {
            if (data[start + i] != ElfSignConstants.SHSTRTAB_MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate the section layout and compute {@link #getTruncateOffset()}.
     * Must be called after {@link #extractSectionInfos} on the original
     * section list.
     *
     * <p>Steps:
     * <ol>
     *   <li>If the SHT is at the end of the file, set the truncate point to
     *       {@code e_shoff}; otherwise the truncate point defaults to the
     *       full file length.</li>
     *   <li>Call {@link #validateSignatureDataAtEnd()} to ensure signature
     *       section data does not overlap with retained section data.</li>
     *   <li>Backward-scan from the last section: skip trailing signature
     *       sections and magic-marked {@code .shstrtab} sections, recording
     *       the minimum offset encountered. The first non-signature,
     *       non-magic-shstrtab section terminates the scan and becomes the
     *       last entry of {@link #getNewSections()}.</li>
     *   <li>Validate that no retained section (excluding {@code SHT_NOBITS},
     *       {@code SHT_NULL}, and zero-size sections) has data beyond the
     *       truncate point — such a condition would indicate stale signature
     *       data not at the file end.</li>
     * </ol>
     *
     * @param inputFileLength actual file size in bytes
     * @return {@code true} if validation succeeded
     * @throws ElfFormatException if a signature section appears mid-list,
     * or a retained section's data extends beyond the truncate point
     */
    public boolean computeOffset(long inputFileLength) throws ElfFormatException {
        int origShnum = origSections.size();
        long minOffset = inputFileLength;
        if ((headerInfo.getShtOff() + headerInfo.getShNum() * headerInfo.getSectionEntrySize()) == inputFileLength) {
            minOffset = headerInfo.getShtOff();
        }

        validateSignatureDataAtEnd();
        for (int i = origShnum - 1; i >= 0; i--) {
            if (ElfSignConstants.isSignatureName(origSections.get(i).getNameString()) || isMagicShstrtab(
                origSections.get(i))) {
                minOffset = origSections.get(i).getOffset();
                continue;
            }
            newSections = new ArrayList<>(origSections.subList(0, i + 1));
            break;
        }
        for (SectionInfo newSection : newSections) {
            if (ElfSignConstants.isSignatureName(newSection.getNameString())) {
                throw new ElfFormatException("Can not to resign while SHT or sign section existed error");
            }
            if (newSection.getType() != ElfTypes.SHT_NULL && newSection.getType() != ElfTypes.SHT_NOBITS
                && newSection.getSize() > 0 && newSection.getOffset() > minOffset) {
                throw new ElfFormatException(
                    "Can not to sign while sign section existed error: " + newSection.getNameString() + " offset="
                        + newSection.getOffset() + " > minOffset=" + minOffset);
            }
        }

        this.truncateOffset = minOffset;
        return true;
    }

    /**
     * Validate that signature section data is at the end of the file, ensuring
     * it can be safely truncated without leaving dead data from retained
     * sections. Checks that the maximum data end of retained sections does not
     * exceed the minimum offset of signature sections. Retained sections
     * exclude SHT_NOBITS, SHT_NULL, and sections with size == 0.
     *
     * @throws ElfFormatException if signature data is not at the end of file
     */
    private void validateSignatureDataAtEnd() throws ElfFormatException {
        long maxRetainedEnd = 0L;
        long minSigOffset = Long.MAX_VALUE;
        boolean hasSignature = false;
        for (SectionInfo sec : origSections) {
            if (ElfSignConstants.isSignatureName(sec.getNameString()) || isMagicShstrtab(sec)) {
                hasSignature = true;
                minSigOffset = Math.min(minSigOffset, sec.getOffset());
            } else if (sec.getType() != ElfTypes.SHT_NULL && sec.getType() != ElfTypes.SHT_NOBITS
                && sec.getSize() > 0) {
                maxRetainedEnd = Math.max(maxRetainedEnd, sec.getOffset() + sec.getSize());
            }
        }
        if (hasSignature && maxRetainedEnd > minSigOffset) {
            throw new ElfFormatException(
                "Signature section data is not at the end of file: max retained end=" + maxRetainedEnd
                    + ", min signature offset=" + minSigOffset);
        }
    }

    /**
     * Load an ELF file and prepare the context for signing. Equivalent to
     * calling {@link #extractHeaderInfo}, {@link #extractSectionInfos}, and
     * {@link #computeOffset} in sequence.
     *
     * @param inputFc readable file channel to the ELF binary
     * @return {@code true} if the file was loaded and validated successfully
     * @throws IOException if reading the file fails
     * @throws ElfFormatException if section layout validation fails
     */
    public boolean load(FileChannel inputFc) throws IOException, ElfFormatException {
        Elfio elfio = new Elfio();
        long inputFileLength = inputFc.size();
        if (!elfio.load(inputFc, true)) {
            LOGGER.error("Failed to load ELF file: {}", inputFileLength);
            return false;
        }

        if (!extractHeaderInfo(elfio)) {
            return false;
        }
        extractSectionInfos(elfio);
        return computeOffset(inputFileLength);
    }

    /**
     * Find the original (non-magic) {@code .shstrtab} section in
     * {@link #getOrigSections()}. On re-sign, this skips the magic-marked
     * {@code .shstrtab} created by a previous sign. Falls back to the
     * section at {@code e_shstrndx} if no magic-free {@code .shstrtab}
     * is found (first sign scenario).
     *
     * @return the original .shstrtab section info, never null
     */
    private SectionInfo findOriginalShstrtab() {
        for (SectionInfo sec : origSections) {
            if (ElfSignConstants.SHSTRTAB_SEC_NAME.equals(sec.getNameString()) && !isMagicShstrtab(sec)) {
                return sec;
            }
        }
        return origSections.get(headerInfo.getSectionNameStrIndex());
    }

    /**
     * Build a new {@code .shstrtab} and append it to {@link #getNewSections()}.
     *
     * <p>The new string table is derived from the original {@code .shstrtab}
     * data. When sections were removed by the backward scan in
     * {@link #computeOffset} (i.e., re-signing), the data is truncated at the
     * maximum name-end offset across all retained sections, then the
     * {@code .shstrtab} name is appended if not already present.
     *
     * <p>The original {@code .shstrtab} is preserved in place as a normal
     * {@code SHT_STRTAB} section; it is not invalidated or removed. On
     * re-sign, the magic-marked {@code .shstrtab} from the previous sign
     * is removed by the backward scan in {@link #computeOffset}.
     *
     * <p>Sets {@link #getNewShStrTabIndex()} to the index of the new entry.
     * Must be called after {@link #computeOffset}; must be called before
     * {@link #addSignSection}.
     *
     * @return {@code true} if the new {@code .shstrtab} was built successfully
     */
    public boolean buildNewShstrtab() {
        SectionInfo orgNameTabSec = findOriginalShstrtab();
        byte[] origData = orgNameTabSec.getData();
        if (origData == null || origData.length == 0) {
            LOGGER.error("Failed to read .shstrtab data");
            return false;
        }
        int truncateAt = origData.length;
        if (origSections.size() != newSections.size()) {
            int maxNameEnd = 0;
            for (SectionInfo sec : newSections) {
                int nameEnd = sec.getNameOffset() + sec.getNameString().getBytes(StandardCharsets.UTF_8).length + 1;
                maxNameEnd = Math.max(maxNameEnd, nameEnd);
            }
            truncateAt = maxNameEnd;
        }
        byte[] truncatedData = Arrays.copyOf(origData, truncateAt);
        byte[] nameBytes = orgNameTabSec.getNameString().getBytes(StandardCharsets.UTF_8);
        int nameEnd = orgNameTabSec.getNameOffset() + nameBytes.length + 1;
        byte[] newShstrtab;
        int newNameOffset;
        if (nameEnd <= truncatedData.length) {
            newShstrtab = truncatedData;
            newNameOffset = orgNameTabSec.getNameOffset();
        } else {
            newShstrtab = Arrays.copyOf(truncatedData, truncatedData.length + nameBytes.length + 1);
            newNameOffset = truncatedData.length;
            System.arraycopy(nameBytes, 0, newShstrtab, newNameOffset, nameBytes.length);
        }
        SectionInfo newNameTabSec = orgNameTabSec.deepCopy();
        newNameTabSec.setNameOffset(newNameOffset);
        newNameTabSec.setSize(newShstrtab.length);
        newNameTabSec.setData(newShstrtab);
        newNameTabSec.setNew(true);
        newShStrTabIndex = (short) newSections.size();
        newNameTabSec.setIndex(newShStrTabIndex);
        newSections.add(newNameTabSec);

        return true;
    }

    /**
     * Append a signature section to {@link #getNewSections()} and register
     * its name in the new {@code .shstrtab} (built by
     * {@link #buildNewShstrtab}). The section type is set to
     * {@code SHT_PROGBITS}.
     *
     * @param name section name (e.g., {@link ElfSignConstants#CODE_SIGN_SEC_NAME})
     * @param addrAlign address alignment in bytes (e.g., page size)
     * @param data section payload, or {@code null} for zero-size
     * @return {@code true} if the section was added successfully
     */
    public boolean addSignSection(String name, long addrAlign, byte[] data) {
        SectionInfo sec = new SectionInfo();
        sec.setNameString(name);
        sec.setType(ElfTypes.SHT_PROGBITS);
        sec.setAddrAlign(addrAlign);
        sec.setData(data);
        sec.setIndex(newSections.size());
        sec.setNew(true);
        if (data != null) {
            sec.setSize(data.length);
        }

        SectionInfo shStrTabSec = newSections.get(newShStrTabIndex);
        byte[] shStrData = shStrTabSec.getData();
        sec.setNameOffset(shStrData.length);
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] newData = Arrays.copyOf(shStrData, shStrData.length + nameBytes.length + 1);
        System.arraycopy(nameBytes, 0, newData, shStrData.length, nameBytes.length);
        shStrTabSec.setData(newData);
        shStrTabSec.setSize(newData.length);

        newSections.add(sec);
        return true;
    }

    /**
     * Append the original {@code e_shstrndx} value and the
     * {@link ElfSignConstants#SHSTRTAB_MAGIC} marker to the end of the new
     * {@code .shstrtab} data. The old shstrndx (2 bytes, big-endian) is
     * written first, followed by the magic marker. Must be called after
     * all {@link #addSignSection} calls and before
     * {@link ElfSignWriter#write}.
     *
     * @return true if the marker was appended successfully
     */
    public boolean finalizeShstrtab() {
        if (newShStrTabIndex < 0 || newShStrTabIndex >= newSections.size()) {
            LOGGER.error("New .shstrtab not built yet");
            return false;
        }
        SectionInfo shstrtab = newSections.get(newShStrTabIndex);
        if (!shstrtab.isNew() || !ElfSignConstants.SHSTRTAB_SEC_NAME.equals(shstrtab.getNameString())) {
            LOGGER.error("Section at newShStrTabIndex is not the new .shstrtab");
            return false;
        }
        byte[] data = shstrtab.getData();
        if (data == null) {
            LOGGER.error("New .shstrtab data is null");
            return false;
        }
        short oldShstrndx = headerInfo.getSectionNameStrIndex();
        int totalAdded = ElfSignConstants.SHSTRNDX_SIZE + ElfSignConstants.SHSTRTAB_MAGIC.length;
        byte[] newData = Arrays.copyOf(data, data.length + totalAdded);
        // Write old e_shstrndx as 2 bytes big-endian, then the magic marker
        newData[data.length] = (byte) ((oldShstrndx >>> 8) & 0xFF);
        newData[data.length + 1] = (byte) (oldShstrndx & 0xFF);
        System.arraycopy(ElfSignConstants.SHSTRTAB_MAGIC, 0, newData, data.length + ElfSignConstants.SHSTRNDX_SIZE,
            ElfSignConstants.SHSTRTAB_MAGIC.length);
        shstrtab.setData(newData);
        shstrtab.setSize(newData.length);
        return true;
    }
}
