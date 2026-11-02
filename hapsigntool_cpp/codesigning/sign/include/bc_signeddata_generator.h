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
#ifndef SIGNATRUETOOLS_BC_SIGNEDDATA_GENERATOR_H
#define SIGNATRUETOOLS_BC_SIGNEDDATA_GENERATOR_H

#include <string>
#include <vector>
#include <memory>

#include "openssl/x509.h"
#include "signeddata_generator.h"
#include "pkcs7_data.h"
#include "signer_config.h"
#include "signer.h"

namespace OHOS {
namespace SignatureTools {

const std::string PLUGINID_OID = "1.3.6.1.4.1.2011.2.376.1.4.2"; // SIGNER_PLUGIN_ID
const std::string PLUGINID_OID_SHORT_NAME = "pluginID";
const std::string PLUGINID_OID_LONG_NAME = "Code Signature Plugin ID";

class BCSignedDataGenerator : public SignedDataGenerator {
public:
    /**
    * Generate signature data with specific content and sign configuration.
    *
    * @param content      unsigned file digest content.
    * @param signerConfig sign configurations.
    * @ret signed data.
    * @return 0:success <0:error
    */
    static int GetSigAlg(SignerConfig* signerConfig, std::string& sigAlg);
    int GenerateSignedData(const std::string& content, SignerConfig* signerConfig, std::string& ret)override;
    void SetOwnerId(const std::string& ownerID);
    void SetPluginId(const std::string& pluginId);

private:
    // @return 0(NID_undef) >0: success(new NID)
    static int CreateNIDFromOID(const std::string& oid, const std::string& shortName,
                                const std::string& longName);
    int PackageSignedData(const std::string& content, const std::shared_ptr<Signer>& signer,
                          const std::string& sigAlg, std::string& ret);
    // @return 0:success <0 :error
    int AddOwnerID(std::vector<PKCS7Attr>& attrs, const std::string& ownerID);
    // @return 0:success <0 :error
    int AddPluginId(std::vector<PKCS7Attr>& attrs, const std::string& pluginId);

private:
    std::string m_ownerID;
    std::string m_pluginId;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_BC_SIGNEDDATA_GENERATOR_H