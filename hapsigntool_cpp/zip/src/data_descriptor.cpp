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

#include "data_descriptor.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {
DataDescriptor* DataDescriptor::GetDataDescriptor(const std::string& bytes)
{
    if (bytes.size() != DES_LENGTH && bytes.size() != DES_LENGTH_ZIP64) {
        SIGNATURE_TOOLS_LOGE("read Data Descriptor failed");
        return nullptr;
    }

    bool isZip64 = (bytes.size() == DES_LENGTH_ZIP64);
    ByteBuffer bf(bytes.c_str(), bytes.size());

    DataDescriptor* data = new DataDescriptor();
    int signValue;
    bf.GetInt32(signValue);
    if (signValue != SIGNATURE) {
        delete data;
        SIGNATURE_TOOLS_LOGE("read Data Descriptor failed");
        return nullptr;
    }
    int crc2Value;
    bf.GetInt32(crc2Value);
    data->SetCrc32(crc2Value);

    if (isZip64) {
        uint64_t dataDescUInt64Value;
        bf.GetUInt64(dataDescUInt64Value);
        data->SetCompressedSize(dataDescUInt64Value);

        bf.GetUInt64(dataDescUInt64Value);
        data->SetUnCompressedSize(dataDescUInt64Value);

        data->SetIsZip64(true);
    } else {
        uint32_t dataDescUInt32Value;
        bf.GetUInt32(dataDescUInt32Value);
        data->SetCompressedSize(dataDescUInt32Value);

        bf.GetUInt32(dataDescUInt32Value);
        data->SetUnCompressedSize(dataDescUInt32Value);
    }

    return data;
}

std::string DataDescriptor::ToBytes()
{
    if (m_isZip64) {
        ByteBuffer bf(DES_LENGTH_ZIP64);
        bf.PutInt32(SIGNATURE);
        bf.PutInt32(m_crc32);
        bf.PutUInt64(m_compressedSize);
        bf.PutUInt64(m_unCompressedSize);
        return bf.ToString();
    }

    ByteBuffer bf(DES_LENGTH);
    bf.PutInt32(SIGNATURE);
    bf.PutInt32(m_crc32);
    bf.PutUInt32(static_cast<uint32_t>(m_compressedSize));
    bf.PutUInt32(static_cast<uint32_t>(m_unCompressedSize));

    return bf.ToString();
}

int DataDescriptor::GetDesLength()
{
    return DES_LENGTH;
}

int DataDescriptor::GetSIGNATURE()
{
    return SIGNATURE;
}

int DataDescriptor::GetCrc32()
{
    return m_crc32;
}

void DataDescriptor::SetCrc32(int crc32)
{
    m_crc32 = crc32;
}

uint64_t DataDescriptor::GetCompressedSize()
{
    return m_compressedSize;
}

void DataDescriptor::SetCompressedSize(uint64_t compressedSize)
{
    m_compressedSize = compressedSize;
}

uint64_t DataDescriptor::GetUnCompressedSize()
{
    return m_unCompressedSize;
}

void DataDescriptor::SetUnCompressedSize(uint64_t unCompressedSize)
{
    m_unCompressedSize = unCompressedSize;
}

bool DataDescriptor::IsZip64()
{
    return m_isZip64;
}

void DataDescriptor::SetIsZip64(bool isZip64)
{
    m_isZip64 = isZip64;
}
} // namespace SignatureTools
} // namespace OHOS