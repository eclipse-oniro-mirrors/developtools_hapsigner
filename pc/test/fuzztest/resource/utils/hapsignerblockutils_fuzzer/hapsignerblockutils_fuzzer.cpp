/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "hap_signer_block_utils.h"

using namespace OHOS::SignatureTools;
namespace OHOS {
namespace SignatureTools {
std::string pathFile = "./zip/tmp.hap";
void HapSignerBlockUtilsFunc(const uint8_t* data, size_t size)
{
    SignatureInfo info;
    HapSignerBlockUtils hapSignerBlockUtils;
    hapSignerBlockUtils.CreatTestZipFile(pathFile, info);

    HapSubSignBlockHead signBlock;
    HapSubSignBlockHead profileBlock;
    HapSubSignBlockHead propertyBlock;
    hapSignerBlockUtils.CreateHapSubSignBlockHead(signBlock, profileBlock, propertyBlock);
}

void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    HapSignerBlockUtilsFunc(data, size);
}
} // namespace SignatureTools
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SignatureTools::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}