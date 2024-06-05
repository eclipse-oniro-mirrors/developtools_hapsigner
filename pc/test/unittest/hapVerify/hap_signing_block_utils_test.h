/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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

#ifndef HAP_SIGNING_BLOCK_UTILS_TEST_H
#define HAP_SIGNING_BLOCK_UTILS_TEST_H

#include <cstdint>
#include <string>

#include "signature_info.h"

#include "test_const.h"

int32_t FindHapSignatureTest001(void);
int32_t VerifyHapIntegrityTest001(void);
int32_t FindEocdInHapTest001(void);
int32_t GetCentralDirectoryOffsetTest001(void);
int32_t ClassifyHapSubSigningBlock001(void);
int32_t ComputeDigestsWithOptionalBlock001(void);
int32_t GetSumOfChunkDigestLenTest001(void);
#endif // HAP_SIGNING_BLOCK_UTILS_TEST_H
