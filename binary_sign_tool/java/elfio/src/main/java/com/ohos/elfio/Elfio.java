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

package com.ohos.elfio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Main ELFIO class for reading and writing ELF files.
 *
 * @since 2026/3/5
 */
public class Elfio {
    private ElfHeader header;

    private List<Section> sections;

    private List<Segment> segments;

    private long currentPos = 0L;

    private boolean loadedFromFile = false; // Track if loaded from file vs newly created

    private FileChannel sourceFileChannel; // Source file channel for streaming

    private ElfioUtils.CompressionInterface compression;

    /**
     * Create a new Elfio instance without compression support.
     * To enable compression, use {@link #Elfio(ElfioUtils.CompressionInterface)}.
     */
    public Elfio() {
        sections = new ArrayList<>();
        segments = new ArrayList<>();
        header = new ElfHeader();
        this.compression = null; // No compression by default
        create(ElfTypes.ELFCLASS32, ElfTypes.ELFDATA2LSB);
    }

    /**
     * Create a new Elfio instance with compression support.
     *
     * @param compression Compression interface implementation, or null for no compression
     */
    public Elfio(ElfioUtils.CompressionInterface compression) {
        this();
        this.compression = compression;
    }

    /**
     * Helper class to pass segment sizes by reference (mimics C++ reference parameters).
     */
    private static class SegmentSizes {
        long memory;
        long filesize;
    }

    /**
     * Create a new ELF file structure.
     *
     * @param fileClass ELFCLASS32 or ELFCLASS64
     * @param encoding ELFDATA2LSB or ELFDATA2MSB
     */
    public void create(byte fileClass, byte encoding) {
        sections.clear();
        segments.clear();
        header.setFileClass(fileClass);
        header.setEncoding(encoding);
        loadedFromFile = false;  // New file, not loaded
        createMandatorySections();
    }

    /**
     * Load an ELF file.
     *
     * @param filename Path to the ELF file
     * @return true if successful
     * @throws IOException if reading fails
     */
    public boolean load(String filename) throws IOException {
        return load(filename, false);
    }

    /**
     * Get the ELF header.
     *
     * @return The ELF header
     */
    public ElfHeader getHeader() {
        return header;
    }

    /**
     * Load an ELF file with lazy loading option.
     *
     * @param filename Path to the ELF file
     * @param isLazy If true, defer loading section/segment data until accessed
     * @return true if successful
     * @throws IOException if reading fails
     */
    public boolean load(String filename, boolean isLazy) throws IOException {
        Path path = Paths.get(filename);
        try (FileChannel fc = FileChannel.open(path, StandardOpenOption.READ)) {
            return load(fc, isLazy);
        }
    }

    /**
     * Load an ELF file from a FileChannel.
     *
     * @param fc The file channel
     * @return true if successful
     * @throws IOException if reading fails
     */
    public boolean load(FileChannel fc) throws IOException {
        return load(fc, false);
    }

    /**
     * Load an ELF file from a FileChannel with lazy loading option.
     *
     * @param fc The file channel
     * @param isLazy If true, defer loading section/segment data until accessed
     * @return true if successful
     * @throws IOException if reading fails
     */
    public boolean load(FileChannel fc, boolean isLazy) throws IOException {
        sections.clear();
        segments.clear();

        // Store source file channel reference for streaming
        this.sourceFileChannel = fc;

        // Read and verify ELF identification
        ByteBuffer identBuffer = ByteBuffer.allocate(16);
        fc.position(0);
        fc.read(identBuffer);
        identBuffer.flip();

        byte[] ident = new byte[16];
        identBuffer.get(ident);

        // Verify magic number
        if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
            return false;
        }

        byte fileClass = ident[ElfTypes.EI_CLASS];
        if (fileClass != ElfTypes.ELFCLASS64 && fileClass != ElfTypes.ELFCLASS32) {
            return false;
        }

        byte encoding = ident[ElfTypes.EI_DATA];
        if (encoding != ElfTypes.ELFDATA2LSB && encoding != ElfTypes.ELFDATA2MSB) {
            return false;
        }

        header.setFileClass(fileClass);
        header.setEncoding(encoding);

        // Load header
        header.load(fc);

        // Load sections
        loadSections(fc, isLazy);

        // Load segments
        loadSegments(fc, isLazy);

        loadedFromFile = true;  // Mark as loaded from file
        return true;
    }

    /**
     * Save the ELF file.
     *
     * @param filename Path to save the file
     * @return true if successful
     * @throws IOException if writing fails
     */
    public boolean save(String filename) throws IOException {
        Path path = Paths.get(filename);
        try (FileChannel fc = FileChannel.open(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING)) {
            return save(fc);
        }
    }

    /**
     * Save the ELF file to a FileChannel.
     *
     * @param fc The file channel
     * @return true if successful
     * @throws IOException if writing fails
     */
    public boolean save(FileChannel fc) throws IOException {
        // Always calculate new layout to handle growing sections (like string tables)
        // or newly added sections correctly.
        return saveWithNewLayout(fc);
    }

    private boolean savePreservingLayout(FileChannel fc) throws IOException {
        // Update header counts
        header.setSegmentNum((short) segments.size());
        header.setSectionNum((short) sections.size());

        // Preserve original offsets - just save without re-layout
        header.save(fc);
        saveSections(fc);
        saveSegments(fc);

        return true;
    }

    private boolean saveWithNewLayout(FileChannel fc) throws IOException {
        // Calculate layout
        header.setSegmentNum((short) segments.size());
        header.setSegmentsOffset(segments.isEmpty() ? 0 : header.getHeaderSize());
        header.setSectionNum((short) sections.size());
        header.setSectionsOffset(0);

        currentPos = header.getHeaderSize() + (long) header.getSegmentEntrySize() * header.getSegmentNum();

        // Calculate segment alignments based on their sections
        calcSegmentAlignment();

        // Layout segments and sections
        if (!layoutSegmentsAndSections(currentPos)) {
            return false;
        }
        layoutSectionsWithoutSegments();
        layoutSectionTable();

        // Save everything
        header.save(fc);
        saveSections(fc);
        saveSegments(fc);

        return true;
    }

    private void loadSections(FileChannel fc) throws IOException {
        loadSections(fc, false);
    }

    private void loadSections(FileChannel fc, boolean isLazy) throws IOException {
        short num = header.getSectionNum();
        int entrySize = header.getSectionEntrySize();
        long offset = header.getSectionsOffset();

        // Entry size validation (from elfio.hpp:492-497)
        byte fileClass = header.getFileClass();
        if ((num != 0 && fileClass == ElfTypes.ELFCLASS64 && entrySize < ElfTypes.SECTION_HEADER_SIZE_64) || (num != 0
            && fileClass == ElfTypes.ELFCLASS32 && entrySize < ElfTypes.SECTION_HEADER_SIZE_32)) {
            throw new IOException("Invalid ELF file: section header entry size too small");
        }

        for (int i = 0; i < num; i++) {
            Section sec = new Section(header.getFileClass(), header.getConvertor(), header.getAddrTranslator(),
                compression);
            sec.setIndex(i);
            sec.setLazy(isLazy);
            sec.load(fc, offset + (long) i * entrySize);
            // Mark address as initialized to preserve it during layout
            sec.setAddress(sec.getAddress());
            sections.add(sec);
        }

        // Load section names
        short shstrndx = header.getSectionNameStrIndex();
        if (shstrndx != ElfTypes.SHN_UNDEF && shstrndx < sections.size()) {
            Section shstrtab = sections.get(shstrndx);
            StringSectionAccessor accessor = new StringSectionAccessor(shstrtab);
            for (Section sec : sections) {
                String name = accessor.getString(sec.getNameStringOffset());
                if (name != null) {
                    sec.setName(name);
                }
            }
        }
    }

    private void loadSegments(FileChannel fc) throws IOException {
        loadSegments(fc, false);
    }

    private void loadSegments(FileChannel fc, boolean isLazy) throws IOException {
        short num = header.getSegmentNum();
        int entrySize = header.getSegmentEntrySize();
        long offset = header.getSegmentsOffset();

        // Entry size validation (from elfio.hpp:608-620)
        byte fileClass = header.getFileClass();
        if ((num != 0 && fileClass == ElfTypes.ELFCLASS64 && entrySize < ElfTypes.SEGMENT_HEADER_SIZE_64) || (num != 0
            && fileClass == ElfTypes.ELFCLASS32 && entrySize < ElfTypes.SEGMENT_HEADER_SIZE_32)) {
            throw new IOException("Invalid ELF file: program header entry size too small");
        }

        long[] sectionOffsets = new long[sections.size()];
        for (int i = 0; i < sections.size(); i++) {
            sectionOffsets[i] = sections.get(i).getOffset();
        }

        for (int i = 0; i < num; i++) {
            Segment seg = new Segment(header.getFileClass(), header.getConvertor(), header.getAddrTranslator());
            seg.setIndex(i);
            seg.setLazy(isLazy);
            seg.load(fc, offset + (long) i * entrySize);
            segments.add(seg);

            // Match sections to segment
            for (int j = 0; j < sections.size(); j++) {
                Section sec = sections.get(j);
                if (checkTlsSectionMapping(sec, seg) && checkOffsetRange(sec, seg)
                    && checkAllocatedSectionVma(sec, seg) && checkEmptyDynamicSection(sec, seg)) {
                    seg.addSectionIndex(j);
                }
            }
            seg.sortSections(sectionOffsets);
        }
    }

    private Boolean checkTlsSectionMapping(Section sec, Segment seg) {
        if ((sec.getFlags() & ElfTypes.SHF_TLS) != 0) {
            if (sec.getType() == ElfTypes.SHT_NOBITS) {
                return seg.getType() == ElfTypes.PT_TLS;
            }
            return seg.getType() == ElfTypes.PT_TLS || seg.getType() == ElfTypes.PT_LOAD
                || seg.getType() == ElfTypes.PT_GNU_RELRO;
        }
        return seg.getType() != ElfTypes.PT_TLS;
    }

    private boolean checkOffsetRange(Section sec, Segment seg) {
        if (sec.getType() == ElfTypes.SHT_NOBITS) {
            return true;
        }
        if (sec.getOffset() < seg.getOffset()) {
            return false;
        }
        long endOffset = seg.getOffset() + seg.getFileSize();
        if (sec.getSize() == 0) {
            return sec.getOffset() + 1 <= endOffset;
        }
        return sec.getOffset() + sec.getSize() <= endOffset;
    }

    private boolean checkAllocatedSectionVma(Section sec, Segment seg) {
        if ((sec.getFlags() & ElfTypes.SHF_ALLOC) == 0) {
            return false;
        }
        if (sec.getAddress() < seg.getVirtualAddress()) {
            return false;
        }
        boolean isTbss = (sec.getType() == ElfTypes.SHT_NOBITS) && ((sec.getFlags() & ElfTypes.SHF_TLS) != 0);
        boolean isTbssInNonTls = isTbss && seg.getType() != ElfTypes.PT_TLS;
        long endVirtualAddress = seg.getVirtualAddress() + seg.getMemorySize();
        if (sec.getSize() == 0 || isTbssInNonTls) {
            return sec.getAddress() + 1 <= endVirtualAddress;
        }
        return sec.getAddress() + sec.getSize() <= endVirtualAddress;
    }

    private boolean checkEmptyDynamicSection(Section sec, Segment seg) {
        if (seg.getType() != ElfTypes.PT_DYNAMIC || seg.getMemorySize() == 0 || sec.getSize() != 0) {
            return true;
        }
        boolean checkOffset = (sec.getType() == ElfTypes.SHT_NOBITS) || (sec.getOffset() > seg.getOffset()
            && sec.getOffset() < seg.getOffset() + seg.getFileSize());
        boolean checkVa = !((sec.getFlags() & ElfTypes.SHF_ALLOC) != 0) || (
            sec.getAddress() > seg.getVirtualAddress() && sec.getAddress() < seg.getMemorySize());
        return checkOffset && checkVa;
    }

    /**
     * Calculate segment alignments based on their sections.
     * If a section has a higher alignment requirement than its segment,
     * the segment's alignment is increased to match.
     */
    private void calcSegmentAlignment() {
        for (Segment seg : segments) {
            for (int i = 0; i < seg.getSectionsNum(); i++) {
                int sectionIdx = seg.getSectionIndexAt(i);
                if (sectionIdx >= 0 && sectionIdx < sections.size()) {
                    Section sec = sections.get(sectionIdx);
                    long sectionAlign = sec.getAddrAlign();
                    long segmentAlign = seg.getAlign();
                    if (sectionAlign > segmentAlign) {
                        seg.setAlign(sectionAlign);
                    }
                }
            }
        }
    }

    private boolean layoutSegmentsAndSections(long startPos) {
        boolean[] sectionGenerated = new boolean[sections.size()];

        // Get segments in proper order
        List<Segment> worklist = getOrderedSegments();

        for (Segment seg : worklist) {
            SegmentSizes sizes = new SegmentSizes();
            long segStartPos = currentPos;

            // Special case: PHDR segment
            // This segment contains the program headers but no sections
            if (seg.getType() == ElfTypes.PT_PHDR && seg.getSectionsNum() == 0) {
                segStartPos = header.getSegmentsOffset();
                sizes.memory = sizes.filesize = (long) header.getSegmentEntrySize() * header.getSegmentNum();
            } else if (seg.isOffsetInitialized() && seg.getOffset() == 0) {
                // Special case: offset initialized to 0
                segStartPos = 0;
                if (seg.getSectionsNum() > 0) {
                    sizes.memory = sizes.filesize = currentPos;
                }
            } else if (seg.getSectionsNum() > 0 && !sectionGenerated[seg.getSectionIndexAt(0)]) {
                // New segments with not generated sections have to be aligned
                long align = (seg.getAlign() > 0) ? seg.getAlign() : 1;
                long curPageAlignment = currentPos % align;
                long reqPageAlignment = seg.getVirtualAddress() % align;
                long error = reqPageAlignment - curPageAlignment;

                currentPos += (align + error) % align;
                segStartPos = currentPos;
            } else if (seg.getSectionsNum() > 0) {
                segStartPos = sections.get(seg.getSectionIndexAt(0)).getOffset();
            }

            // Write segment's data
            if (!writeSegmentData(seg, sectionGenerated, sizes, segStartPos)) {
                return false;
            }

            seg.setFileSize(sizes.filesize);

            // If we already have a memory size from loading an elf file (value > 0),
            // it must not shrink!
            // Memory size may be bigger than file size and it is the loader's job to do something
            // with the surplus bytes in memory, like initializing them with a defined value.
            if (seg.getMemorySize() < sizes.memory) {
                seg.setMemorySize(sizes.memory);
            }

            seg.setOffset(segStartPos);
        }

        return true;
    }

    /**
     * Write segment data and layout sections.
     * This method mirrors the C++ write_segment_data() implementation.
     */
    private boolean writeSegmentData(Segment seg, boolean[] sectionGenerated, SegmentSizes sizes, long segStartPos) {
        for (int j = 0; j < seg.getSectionsNum(); j++) {
            int index = seg.getSectionIndexAt(j);
            if (index >= sections.size()) {
                continue;
            }

            Section sec = sections.get(index);

            // The NULL section is always generated
            if (sec.getType() == ElfTypes.SHT_NULL) {
                sectionGenerated[index] = true;
                continue;
            }

            Long sectionAlign = computeSectionAlignment(sec, seg, sectionGenerated[index], segStartPos, sizes);
            if (sectionAlign == null) {
                return false;
            }

            updateSegmentSizes(seg, sec, sectionAlign, sizes);

            // Nothing to be done when generating nested segments
            if (sectionGenerated[index]) {
                continue;
            }

            currentPos += sectionAlign;

            // Set the section addresses when missing
            if (!sec.isAddressInitialized()) {
                sec.setAddress(seg.getVirtualAddress() + currentPos - segStartPos);
            }

            // For newly added sections (no address initialized), always set offset
            // to respect alignment requirements
            // For loaded sections (address initialized), preserve their offset
            if (sec.getIndex() != 0 && !sectionGenerated[index]) {
                sec.setOffset(currentPos);
            }

            if (sec.getType() != ElfTypes.SHT_NOBITS) {
                currentPos += sec.getSize();
            }

            sectionGenerated[index] = true;
        }

        return true;
    }

    private Long computeSectionAlignment(Section sec, Segment seg, boolean sectionGenerated, long segStartPos,
                                         SegmentSizes sizes) {
        if (sectionGenerated) {
            return sec.getOffset() - segStartPos - sizes.filesize;
        }
        if (sec.isAddressInitialized() && sec.getType() != ElfTypes.SHT_NOBITS && sec.getType() != ElfTypes.SHT_NULL
            && sec.getSize() != 0 && (sec.getFlags() & ElfTypes.SHF_ALLOC) == ElfTypes.SHF_ALLOC) {
            long reqOffset = sec.getAddress() - seg.getVirtualAddress();
            long curOffset = currentPos - segStartPos;
            if (reqOffset < curOffset) {
                return null;
            }
            return reqOffset - curOffset;
        }
        if (!sec.isAddressInitialized()) {
            long align = sec.getAddrAlign() == 0 ? 1 : sec.getAddrAlign();
            long error = currentPos % align;
            return (align - error) % align;
        }
        return 0L;
    }

    private void updateSegmentSizes(Segment seg, Section sec, long sectionAlign, SegmentSizes sizes) {
        boolean isAllocated = (sec.getFlags() & ElfTypes.SHF_ALLOC) == ElfTypes.SHF_ALLOC;
        boolean isTbssInNonTls = ((sec.getFlags() & ElfTypes.SHF_TLS) == ElfTypes.SHF_TLS)
            && (seg.getType() != ElfTypes.PT_TLS) && (sec.getType() == ElfTypes.SHT_NOBITS);
        if (isAllocated && !isTbssInNonTls) {
            sizes.memory += sec.getSize() + sectionAlign;
        }
        if (sec.getType() != ElfTypes.SHT_NOBITS) {
            sizes.filesize += sec.getSize() + sectionAlign;
        }
    }

    private void layoutSectionsWithoutSegments() {
        for (int i = 0; i < sections.size(); i++) {
            if (isSectionWithoutSegment(i)) {
                Section sec = sections.get(i);

                long align = sec.getAddrAlign();
                if (align == 0) {
                    align = 1;
                }

                if (align > 1 && currentPos % align != 0) {
                    currentPos += align - (currentPos % align);
                }

                if (sec.getIndex() != 0) {
                    sec.setOffset(currentPos);
                }

                if (sec.getType() != ElfTypes.SHT_NOBITS && sec.getType() != ElfTypes.SHT_NULL) {
                    currentPos += sec.getSize();
                }
            }
        }
    }

    /**
     * Layout the section table at the end of the file.
     */
    private void layoutSectionTable() {
        // Simply place the section table at the end for now
        // Align to 4 bytes
        long alignmentError = currentPos % 4;
        currentPos += (4 - alignmentError) % 4;
        header.setSectionsOffset(currentPos);
    }

    private boolean isSectionWithoutSegment(int sectionIndex) {
        for (Segment seg : segments) {
            for (int i = 0; i < seg.getSectionsNum(); i++) {
                if (seg.getSectionIndexAt(i) == sectionIndex) {
                    return false;
                }
            }
        }
        return true;
    }

    private long alignPosition(long pos, long align) {
        if (align == 0) {
            return pos;
        }
        long remainder = pos % align;
        if (remainder == 0) {
            return pos;
        }
        return pos + (align - remainder);
    }

    /**
     * Check if segments1's sections are a subset of segments2's sections.
     *
     * @param seg1 First segment
     * @param seg2 Second segment
     * @return true if seg1's sections are a subset of seg2's sections
     */
    private static boolean isSubsequenceOf(Segment seg1, Segment seg2) {
        List<Integer> sections1 = new ArrayList<>();
        List<Integer> sections2 = new ArrayList<>();

        for (int i = 0; i < seg1.getSectionsNum(); i++) {
            sections1.add(seg1.getSectionIndexAt(i));
        }
        for (int i = 0; i < seg2.getSectionsNum(); i++) {
            sections2.add(seg2.getSectionIndexAt(i));
        }

        // Return true if sections1 is a subset of sections2 and smaller
        if (sections1.size() < sections2.size()) {
            Collections.sort(sections1);
            Collections.sort(sections2);

            // Check if sections1 is a subset of sections2
            return containsAll(sections2, sections1);
        }

        return false;
    }

    /**
     * Check if list contains all elements of another list (both must be sorted).
     */
    private static boolean containsAll(List<Integer> list, List<Integer> sublist) {
        int i = 0; // index in list
        int j = 0; // index in sublist

        while (i < list.size() && j < sublist.size()) {
            int cmp = Integer.compareUnsigned(list.get(i), sublist.get(j));
            if (cmp == 0) {
                j++; // Found match, move to next element in sublist
            }
            i++;
        }

        return j == sublist.size();
    }

    /**
     * Get segments in proper order for layout.
     * Segments with offset=0 come first, followed by segments that are not
     * subsequences of other segments. Subsequence segments come last.
     *
     * @return List of segments in proper order
     */
    private List<Segment> getOrderedSegments() {
        List<Segment> result = new ArrayList<>();
        List<Segment> worklist = new ArrayList<>(segments);

        // Bring segments which start at offset 0 to the front
        int nextSlot = 0;
        for (int i = 0; i < worklist.size(); i++) {
            if (i != nextSlot && worklist.get(i).isOffsetInitialized() && worklist.get(i).getOffset() == 0) {
                if (worklist.get(nextSlot).isOffsetInitialized() && worklist.get(nextSlot).getOffset() == 0) {
                    nextSlot++;
                }
                // Swap
                Segment temp = worklist.get(i);
                worklist.set(i, worklist.get(nextSlot));
                worklist.set(nextSlot, temp);
                nextSlot++;
            }
        }

        // Sort so that subsequences come last
        while (!worklist.isEmpty()) {
            Segment seg = worklist.get(0);
            worklist.remove(0);

            int i;
            for (i = 0; i < worklist.size(); i++) {
                if (isSubsequenceOf(seg, worklist.get(i))) {
                    break;
                }
            }

            if (i < worklist.size()) {
                // Is a subsequence, move to end
                worklist.add(seg);
            } else {
                result.add(seg);
            }
        }

        return result;
    }

    private void saveSections(FileChannel fc) throws IOException {
        for (Section sec : sections) {
            long headerPos = header.getSectionsOffset() + (long) header.getSectionEntrySize() * sec.getIndex();
            sec.save(fc, headerPos, sec.getOffset());
        }
    }

    private void saveSegments(FileChannel fc) throws IOException {
        for (Segment seg : segments) {
            long headerPos = header.getSegmentsOffset() + (long) header.getSegmentEntrySize() * seg.getIndex();
            seg.save(fc, headerPos, seg.getOffset());
        }
    }

    private void createMandatorySections() {
        // Create null section
        Section sec0 = new Section(header.getFileClass(), header.getConvertor(), header.getAddrTranslator(),
            compression);
        sec0.setIndex(0);
        sec0.setName("");
        sec0.setType(ElfTypes.SHT_NULL);
        sections.add(sec0);

        // Create .shstrtab
        header.setSectionNameStrIndex((short) 1);
        Section shstrtab = new Section(header.getFileClass(), header.getConvertor(), header.getAddrTranslator(),
            compression);
        shstrtab.setIndex(1);
        shstrtab.setName(".shstrtab");
        shstrtab.setType(ElfTypes.SHT_STRTAB);
        shstrtab.setAddrAlign(1);
        sections.add(shstrtab);
    }

    // Getters for header properties
    public byte getElfClass() {
        return header.getFileClass();
    }

    public byte getElfVersion() {
        return header.getElfVersion();
    }

    public byte getEncoding() {
        return header.getEncoding();
    }

    public int getVersion() {
        return header.getVersion();
    }

    public short getHeaderSize() {
        return header.getHeaderSize();
    }

    public short getSectionEntrySize() {
        return header.getSectionEntrySize();
    }

    public short getSegmentEntrySize() {
        return header.getSegmentEntrySize();
    }

    public byte getOsAbi() {
        return header.getOsAbi();
    }

    public byte getAbiVersion() {
        return header.getAbiVersion();
    }

    public short getType() {
        return header.getType();
    }

    public short getMachine() {
        return header.getMachine();
    }

    public int getFlags() {
        return header.getFlags();
    }

    public long getEntry() {
        return header.getEntry();
    }

    public long getSectionsOffset() {
        return header.getSectionsOffset();
    }

    public long getSegmentsOffset() {
        return header.getSegmentsOffset();
    }

    public short getSectionNameStrIndex() {
        return header.getSectionNameStrIndex();
    }

    public ElfioUtils.EndiannessConvertor getConvertor() {
        return header.getConvertor();
    }

    public boolean getLoadedFromFile() {
        return loadedFromFile;
    }

    /**
     * Get source file channel (for streaming).
     *
     * @return Source file channel
     */
    public FileChannel getSourceFileChannel() {
        return sourceFileChannel;
    }

    /**
     * Set source file channel (for streaming).
     * This should be called after loading from a file if the file channel
     * was closed and needs to be reopened for streaming.
     *
     * @param fc Source file channel
     */
    public void setSourceFileChannel(FileChannel fc) {
        this.sourceFileChannel = fc;
    }

    // Setters for header properties
    public void setOsAbi(byte osAbi) {
        header.setOsAbi(osAbi);
    }

    public void setAbiVersion(byte abiVersion) {
        header.setAbiVersion(abiVersion);
    }

    public void setType(short type) {
        header.setType(type);
    }

    public void setMachine(short machine) {
        header.setMachine(machine);
    }

    public void setFlags(int flags) {
        header.setFlags(flags);
    }

    public void setEntry(long entry) {
        header.setEntry(entry);
    }

    public void setSectionsOffset(long offset) {
        header.setSectionsOffset(offset);
    }

    public void setSegmentsOffset(long offset) {
        header.setSegmentsOffset(offset);
    }

    public void setSectionNameStrIndex(short index) {
        header.setSectionNameStrIndex(index);
    }

    // Section access
    public int getSectionsCount() {
        return sections.size();
    }

    public Section getSection(int index) {
        if (index < 0 || index >= sections.size()) {
            return null;
        }
        return sections.get(index);
    }

    public Section getSection(String name) {
        for (Section sec : sections) {
            if (sec.getName().equals(name)) {
                return sec;
            }
        }
        return null;
    }

    public Section addSection(String name) {
        return addSection(name, 0);
    }

    /**
     * Add a new section with specified alignment.
     *
     * @param name Section name
     * @param addrAlign Address alignment (0 to use default)
     * @return The newly created section
     */
    public Section addSection(String name, long addrAlign) {
        Section newSection = new Section(header.getFileClass(), header.getConvertor(), header.getAddrTranslator(),
            compression);
        newSection.setName(name);
        newSection.setIndex(sections.size());

        // Set parent reference for automatic offset recalculation
        newSection.setParentElfio(this);

        // Set alignment if specified
        if (addrAlign > 0) {
            newSection.setAddrAlign(addrAlign);
        }

        // Add to string table
        short strIndex = header.getSectionNameStrIndex();
        Section stringTable = sections.get(strIndex);
        StringSectionAccessor strWriter = new StringSectionAccessor(stringTable);
        int pos = strWriter.addString(name);
        newSection.setNameStringOffset(pos);

        // Calculate offset for the new section
        // Find the end of the last section with actual data
        long newOffset = calculateSectionOffset();

        // Apply alignment
        long align = newSection.getAddrAlign();
        if (align > 1 && newOffset % align != 0) {
            newOffset += align - (newOffset % align);
        }

        newSection.setOffset(newOffset);
        sections.add(newSection);
        loadedFromFile = false;  // Modified, need to recalculate layout
        return newSection;
    }

    /**
     * Realign a section's offset after changing its alignment.
     * Call this after setAddrAlign() to update the section's offset.
     *
     * @param section The section to realign
     */
    public void realignSection(Section section) {
        if (section == null || section.isAddressInitialized()) {
            return; // Skip sections with address initialized (loaded from file)
        }

        // Calculate the base offset
        long newOffset = calculateSectionOffset();

        // Apply alignment
        long align = section.getAddrAlign();
        if (align == 0) {
            align = 1;
        }
        if (align > 1 && newOffset % align != 0) {
            newOffset += align - (newOffset % align);
        }

        section.setOffset(newOffset);
    }

    /**
     * Calculate the offset for a new section based on existing sections.
     *
     * @return The offset where a new section should be placed
     */
    private long calculateSectionOffset() {
        long newOffset = header.getHeaderSize() + (long) header.getSegmentEntrySize() * header.getSegmentNum();

        for (Section sec : sections) {
            if (sec.getType() != ElfTypes.SHT_NOBITS && sec.getType() != ElfTypes.SHT_NULL) {
                long sectionEnd = sec.getOffset() + sec.getSize();
                if (sectionEnd > newOffset) {
                    newOffset = sectionEnd;
                }
            }
        }
        return newOffset;
    }

    /**
     * Remove the last section of the ELF file if its name matches the provided name.
     * Mandatory sections (index 0 and 1) cannot be removed.
     *
     * @param sectionName The expected name of the last section to be removed
     * @return true if successful, false otherwise
     */
    public boolean removeLastSection(String sectionName) {
        if (sections.size() <= 2) {
            return false; // Cannot remove mandatory sections (null and shstrtab)
        }

        int lastIndex = sections.size() - 1;
        Section lastSection = sections.get(lastIndex);

        // Verify if the name matches the name in the ELF
        String actualName = lastSection.getName();
        if (sectionName == null || !sectionName.equals(actualName)) {
            return false;
        }

        // Remove name from string table if it was the last entry
        short shstrndx = header.getSectionNameStrIndex();
        if (shstrndx != ElfTypes.SHN_UNDEF && shstrndx < sections.size()) {
            Section shstrtab = sections.get(shstrndx);
            int nameOffset = lastSection.getNameStringOffset();
            if (actualName != null && nameOffset + actualName.length() + 1 == shstrtab.getSize()) {
                // It was at the end of the string table, we can shrink it
                shstrtab.setSize(nameOffset);
            }
        }

        sections.remove(lastIndex);
        loadedFromFile = false; // Layout needs to be recalculated
        return true;
    }

    // Segment access
    public int getSegmentsCount() {
        return segments.size();
    }

    public Segment getSegment(int index) {
        if (index < 0 || index >= segments.size()) {
            return null;
        }
        return segments.get(index);
    }

    public Segment addSegment() {
        Segment newSegment = new Segment(header.getFileClass(), header.getConvertor(), header.getAddrTranslator());
        newSegment.setIndex(segments.size());
        segments.add(newSegment);
        loadedFromFile = false;  // Modified, need to recalculate layout
        return newSegment;
    }

    /**
     * Set address translation table for mapping virtual to physical addresses.
     *
     * @param addrTrans List of address translations
     */
    public void setAddressTranslation(java.util.List<ElfioUtils.AddressTranslation> addrTrans) {
        header.getAddrTranslator().setAddressTranslation(addrTrans);
    }

    /**
     * Get the default entry size for a given section type.
     *
     * @param sectionType The section type
     * @return Default entry size, or 0 if unknown
     */
    public long getDefaultEntrySize(int sectionType) {
        boolean is64Bit = (header.getFileClass() == ElfTypes.ELFCLASS64);
        switch (sectionType) {
            case ElfTypes.SHT_RELA:
                return is64Bit ? ElfTypes.RELA_ENTRY_SIZE_64 : ElfTypes.RELA_ENTRY_SIZE_32;
            case ElfTypes.SHT_REL:
                return is64Bit ? ElfTypes.REL_ENTRY_SIZE_64 : ElfTypes.REL_ENTRY_SIZE_32;
            case ElfTypes.SHT_SYMTAB:
            case ElfTypes.SHT_DYNSYM:
                return is64Bit ? ElfTypes.SYM_ENTRY_SIZE_64 : ElfTypes.SYM_ENTRY_SIZE_32;
            case ElfTypes.SHT_DYNAMIC:
                return is64Bit ? ElfTypes.DYN_ENTRY_SIZE_64 : ElfTypes.DYN_ENTRY_SIZE_32;
            default:
                return 0;
        }
    }

    /**
     * Validate the ELF file structure.
     *
     * @return Empty string if valid, error message(s) if problems found
     */
    public String validate() {
        StringBuilder errors = new StringBuilder();

        // Check for overlapping sections in the file
        for (int i = 0; i < sections.size(); i++) {
            for (int j = i + 1; j < sections.size(); j++) {
                Section a = sections.get(i);
                Section b = sections.get(j);

                boolean aHasBits = (a.getType() & ElfTypes.SHT_NOBITS) == 0;
                boolean bHasBits = (b.getType() & ElfTypes.SHT_NOBITS) == 0;
                boolean aHasData = a.getSize() > 0;
                boolean bHasData = b.getSize() > 0;
                boolean aValidOffset = a.getOffset() > 0;
                boolean bValidOffset = b.getOffset() > 0;

                if (aHasBits && bHasBits && aHasData && bHasData && aValidOffset && bValidOffset) {
                    if (isOffsetInSection(a.getOffset(), b) || isOffsetInSection(a.getOffset() + a.getSize() - 1, b)
                        || isOffsetInSection(b.getOffset(), a) || isOffsetInSection(b.getOffset() + b.getSize() - 1,
                        a)) {
                        errors.append("Sections ")
                            .append(a.getName())
                            .append(" and ")
                            .append(b.getName())
                            .append(" overlap in file\n");
                    }
                }
            }
        }

        // Check for conflicting section / program header table addresses
        for (int h = 0; h < segments.size(); h++) {
            Segment seg = segments.get(h);
            Section sec = findProgSectionForOffset(seg.getOffset());

            if (sec != null && seg.getType() == ElfTypes.PT_LOAD && seg.getFileSize() > 0) {
                long secAddr = getVirtualAddr(seg.getOffset(), sec);
                if (secAddr != seg.getVirtualAddress()) {
                    errors.append("Virtual address of segment ")
                        .append(h)
                        .append(" (0x")
                        .append(Long.toHexString(seg.getVirtualAddress()))
                        .append(") conflicts with address of section ")
                        .append(sec.getName())
                        .append(" (0x")
                        .append(Long.toHexString(secAddr))
                        .append(") at offset 0x")
                        .append(Long.toHexString(seg.getOffset()))
                        .append("\n");
                }
            }
        }

        return errors.toString();
    }

    private boolean isOffsetInSection(long offset, Section sec) {
        return offset >= sec.getOffset() && offset < (sec.getOffset() + sec.getSize());
    }

    private long getVirtualAddr(long offset, Section sec) {
        return sec.getAddress() + offset - sec.getOffset();
    }

    private Section findProgSectionForOffset(long offset) {
        for (Section sec : sections) {
            if (sec.getType() == ElfTypes.SHT_PROGBITS && isOffsetInSection(offset, sec)) {
                return sec;
            }
        }
        return null;
    }
}
