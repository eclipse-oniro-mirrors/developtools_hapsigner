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

package com.ohos.hapsigntool.entity;

import java.nio.charset.StandardCharsets;

/**
 * ELF signing section name constants shared by signing, comparison, and
 * verification components.
 *
 * @since 2026/09/08
 */
public class ElfSignConstants {
    /**
     * Section name for the .shstrtab section.
     */
    public static final String SHSTRTAB_SEC_NAME = ".shstrtab";

    /**
     * Section name for the code-signature section.
     */
    public static final String CODE_SIGN_SEC_NAME = ".codesign";

    /**
     * Section name for the permission section.
     */
    public static final String PERMISSION_SEC_NAME = ".permission";

    /**
     * Section name for the profile section.
     */
    public static final String PROFILE_SEC_NAME = ".profile";

    /**
     * Magic marker appended to the end of self-created {@code .shstrtab}
     * data so that re-signing can identify and remove it. The marker does
     * not affect string table offsets because it sits after all
     * null-terminated name entries.
     */
    public static final byte[] SHSTRTAB_MAGIC = "OHOSCSIG".getBytes(StandardCharsets.US_ASCII);

    /**
     * Size in bytes of the original {@code e_shstrndx} value stored before
     * the {@link #SHSTRTAB_MAGIC} marker in the new {@code .shstrtab}.
     * The 2-byte value is written in big-endian order so it can be read
     * back without the ELF endianess convertor.
     */
    public static final int SHSTRNDX_SIZE = Short.BYTES;

    private ElfSignConstants() {
    }

    /**
     * Check if a section name is a signature section name.
     *
     * @param name section name
     * @return true if signature section
     */
    public static boolean isSignatureName(String name) {
        return CODE_SIGN_SEC_NAME.equals(name) || PERMISSION_SEC_NAME.equals(name) || PROFILE_SEC_NAME.equals(name);
    }
}
