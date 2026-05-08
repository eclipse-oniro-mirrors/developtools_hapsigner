/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "fs_verity_descriptor.h"

namespace OHOS {
namespace SignatureTools {
FsVerityDescriptor::FsVerityDescriptor()
{}

void FsVerityDescriptor::ToByteArray(std::vector<int8_t> &ret)
{
    std::unique_ptr<ByteBuffer> buffer = std::make_unique<ByteBuffer>(ByteBuffer(DESCRIPTOR_SIZE));
    buffer->PutByte(VERSION);
    buffer->PutByte(hashAlgorithm);
    buffer->PutByte(log2BlockSize);
    if (saltSize > SALT_SIZE) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Salt is too long");
        ret = std::vector<int8_t>();
        return;
    }
    buffer->PutByte(saltSize);
    buffer->PutInt32(signSize);
    buffer->PutInt64(fileSize);
    WriteBytesWithSize(buffer.get(), rawRootHash, ROOT_HASH_FILED_SIZE);
    WriteBytesWithSize(buffer.get(), salt, SALT_SIZE);
    buffer->PutInt32(flags);
    std::vector<int8_t> emptyVector;
    WriteBytesWithSize(buffer.get(), emptyVector, RESERVED_SIZE_AFTER_FLAGS);
    buffer->PutInt64(merkleTreeOffset);
    WriteBytesWithSize(buffer.get(), emptyVector, RESERVED_SIZE_AFTER_TREE_OFFSET);
    buffer->PutByte(csVersion);
    buffer->Flip();
    char dataArr[DESCRIPTOR_SIZE] = { 0 };
    buffer->GetData(dataArr, DESCRIPTOR_SIZE);
    ret = std::vector<int8_t>(dataArr, dataArr + DESCRIPTOR_SIZE);
    return;
}

void FsVerityDescriptor::GetByteForGenerateDigest(std::vector<int8_t> &ret)
{
    std::unique_ptr<ByteBuffer> buffer = std::make_unique<ByteBuffer>(ByteBuffer(DESCRIPTOR_SIZE));
    buffer->PutByte(VERSION);
    buffer->PutByte(hashAlgorithm);
    buffer->PutByte(log2BlockSize);
    if (saltSize > SALT_SIZE) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Salt is too long");
        ret = std::vector<int8_t>();
        return;
    }
    buffer->PutByte(saltSize);
    buffer->PutInt32(0);
    buffer->PutInt64(fileSize);
    WriteBytesWithSize(buffer.get(), rawRootHash, ROOT_HASH_FILED_SIZE);
    WriteBytesWithSize(buffer.get(), salt, SALT_SIZE);
    buffer->PutInt32(flags);
    std::vector<int8_t> emptyVector;
    WriteBytesWithSize(buffer.get(), emptyVector, RESERVED_SIZE_AFTER_FLAGS);
    buffer->PutInt64(merkleTreeOffset);
    WriteBytesWithSize(buffer.get(), emptyVector, RESERVED_SIZE_AFTER_TREE_OFFSET);
    buffer->PutByte(csVersion);
    buffer->Flip();
    char dataArr[DESCRIPTOR_SIZE] = { 0 };
    buffer->GetData(dataArr, DESCRIPTOR_SIZE);
    ret = std::vector<int8_t>(dataArr, dataArr + DESCRIPTOR_SIZE);
    return;
}

void FsVerityDescriptor::WriteBytesWithSize(ByteBuffer* buffer, std::vector<int8_t>& src, int size)
{
    int pos = buffer->GetPosition();
    if (!src.empty()) {
        if (src.size() > size) {
            buffer->PutData(src.data(), size);
        } else {
            buffer->PutData(src.data(), src.size());
        }
    }
    buffer->SetPosition(pos + size);
}
} // namespace SignatureTools
} // namespace OHOS