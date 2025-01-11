/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.codesigning.utils;

import com.ohos.hapsigntool.codesigning.exception.CodeSignErrMsg;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;

/**
 * CMS utils class
 *
 * @since 2023/06/05
 */
public class CmsUtils {
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Private constructor
     */
    private CmsUtils() {
    }

    private static void isCollectionValid(Collection<X509CertificateHolder> collection)
        throws OperatorCreationException {
        if (collection == null) {
            throw new OperatorCreationException(
                CodeSignErrMsg.CERTIFICATES_CONFIGURE_ERROR.toString("No matched cert"));
        }
        if (collection.size() != 1) {
            throw new OperatorCreationException(CodeSignErrMsg.CERTIFICATES_CONFIGURE_ERROR.toString(
                "More than one matched certs, matched certs size: " + collection.size()));
        }
    }

    @SuppressWarnings("unchecked")
    private static boolean verifyCmsSignedData(CMSSignedData cmsSignedData) throws CMSException {
        return cmsSignedData.verifySignatures(signId -> {
            Collection<X509CertificateHolder> collection = cmsSignedData.getCertificates().getMatches(signId);
            isCollectionValid(collection);
            X509CertificateHolder cert = collection.iterator().next();
            try {
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert);
            } catch (CertificateException e) {
                throw new OperatorCreationException(
                    CodeSignErrMsg.CODE_SIGN_INTERNAL_ERROR.toString("Verify BC signatures failed: " + e.getMessage()),
                    e);
            }
        });
    }

    /**
     * Verify signed data using an unsigned data digest
     *
     * @param unsignedDataDigest unsigned data digest
     * @param signedData         signed data
     * @return true if verify success
     * @throws CMSException if error
     */
    public static boolean verifySignDataWithUnsignedDataDigest(byte[] unsignedDataDigest, byte[] signedData)
        throws CMSException {
        CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(unsignedDataDigest), signedData);
        return verifyCmsSignedData(cmsSignedData);
    }
}
