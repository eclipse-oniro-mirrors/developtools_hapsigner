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
#ifndef SIGNATURETOOLS_CMS_UTILS_H
#define SIGNATURETOOLS_CMS_UTILS_H
#include <vector>
#include <string>
#include <sstream>
#include "signature_tools_log.h"
#include "pkcs7_data.h"
namespace OHOS {
    namespace SignatureTools {
        class CmsUtils {
        private:
            CmsUtils();
        public:
            static bool VerifySignDataWithUnsignedDataDigest(const std::vector<int8_t>& unsignedDataDigest,
                const std::vector<int8_t>& signedData);
            static bool CheckOwnerID(const std::string& signature, const std::string& profileOwnerID,
                const std::string& profileType);
            static int CreateNIDFromOID(const std::string& oid, const std::string& shortName,
                const std::string& longName);
        };
    }
}
#endif