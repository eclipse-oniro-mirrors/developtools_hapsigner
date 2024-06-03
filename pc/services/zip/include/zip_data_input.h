/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SIGNERTOOLS_ZIP_DATAINPUT_H
#define SIGNERTOOLS_ZIP_DATAINPUT_H

#include "byte_buffer.h"
#include "data_source.h"
#include "random_access_file_zip_data_output.h"
#include <memory>

namespace OHOS {
    namespace SignatureTools {
        class ZipDataInput {
        public:
            virtual ~ZipDataInput()
            {
            }

            /**
             * Get how many bytes are contained in this data input.
             *
             * @return this data input size
             */
            virtual long Size() = 0;

            /**
             * Copy the specified data block into the destination ZipDataOutput
             *
             * @param offset offset index at the ZipDataInput
             * @param size size of the data block
             * @param buffer the destination ZipDataOutput
             * @throws IOException when IO error occurred
             */
            virtual bool CopyTo(long offset, int size, ByteBuffer& buffer) = 0;

            /**
             * Create a ByteBuffer which contain the specified data block from this ZipDataInput
             *
             * @param offset offset index at the ZipDataInput
             * @param size size of the data block
             * @return a ByteBuffer
             * @throws IOException when IO error occurred
             */
            virtual ByteBuffer CreateByteBuffer(long  offset, int size) = 0;

            /**
             * Create a new DataSource whose content is shared by this DataSource
             *
             * @param offset offset index at the DataSource
             * @param size size of the data block
             * @return new DataSource
             */
            virtual DataSource* Slice(long offset, long size) = 0;
        };
    }
}
#endif
