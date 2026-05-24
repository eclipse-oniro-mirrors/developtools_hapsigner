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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Define class of permission signing block.
 *
 * @since 2026-05-07
 */
public class PermissionSignBlock {
    private static final int HEADER_SIZE = 18;

    private final long magicNumber;
    private final int signAlgId;
    private final byte[] digestContents;
    private final short digestCount;

    public PermissionSignBlock(int signAlgId, byte[] digestContents, int digestCount, long magicNumber) {
        Objects.requireNonNull(digestContents, "digestContents can not be null");
        if (digestCount > Short.MAX_VALUE || digestCount < 0) {
            throw new IllegalArgumentException("digestCount " + digestCount + " out of range");
        }
        this.signAlgId = signAlgId;
        this.digestContents = digestContents;
        this.digestCount = (short) digestCount;
        this.magicNumber = magicNumber;
    }

    /**
     * Return permission to be signing content
     *
     * @return permission to be signing content
     * @throws IOException if signing block size less than block header
     */
    public byte[] toByteArray() throws IOException {
        int size = HEADER_SIZE + digestContents.length;
        if (size < 0) {
            throw new IOException("Permission signing block size '" + size + "' out of range.");
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.putLong(magicNumber);
        byteBuffer.putInt(signAlgId);
        byteBuffer.putInt(digestContents.length);
        byteBuffer.putShort(digestCount);
        byteBuffer.put(digestContents);
        if (byteBuffer.hasArray()) {
            return byteBuffer.array();
        }
        byteBuffer.flip();
        byte[] result = new byte[byteBuffer.remaining()];
        byteBuffer.get(result);
        return result;
    }
}
