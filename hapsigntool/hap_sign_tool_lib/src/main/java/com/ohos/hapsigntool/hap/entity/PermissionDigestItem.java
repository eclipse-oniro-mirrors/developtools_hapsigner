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

package com.ohos.hapsigntool.hap.entity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;

/**
 * Permission signing digest item
 *
 * @since 2026/05/07
 */
public class PermissionDigestItem {
    private final int type;
    private final byte[] digest;

    public PermissionDigestItem(int type, byte[] digest) {
        Objects.requireNonNull(digest, "digest can not be null");
        this.type = type;
        this.digest = digest;
    }

    /**
     * Return the contents of permission item as a byte array.
     *
     * @return the contents of permission item.
     * @throws IOException if an I/O error occurs
     */
    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(digest.length + 4);
        out.write(type & 0xff);
        out.write((type >>> 8) & 0xff);
        out.write((type >>> 16) & 0xff);
        out.write((type >>> 24) & 0xff);
        out.write(digest);
        return out.toByteArray();
    }

    public byte[] getDigest() {
        return digest.clone();
    }

    public int getType() {
        return type;
    }
}
