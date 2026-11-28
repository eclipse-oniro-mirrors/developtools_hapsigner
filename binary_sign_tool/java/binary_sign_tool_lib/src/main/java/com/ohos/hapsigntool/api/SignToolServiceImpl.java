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

package com.ohos.hapsigntool.api;

import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.hap.provider.LocalJKSSignProvider;
import com.ohos.hapsigntool.hap.provider.RemoteSignProvider;
import com.ohos.hapsigntool.hap.provider.SelfSignSignProvider;
import com.ohos.hapsigntool.hap.provider.SignProvider;
import com.ohos.hapsigntool.utils.LogUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Main entry of lib.
 *
 * @since 2021/12/28
 */
public class SignToolServiceImpl implements ServiceApi {
    /**
     * Logger.
     */
    private static final LogUtils LOGGER = new LogUtils(ServiceApi.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Sign for hap/elf files.
     *
     * @param options options
     * @return Sign or not
     */
    @Override
    public boolean signHap(Options options) {
        String mode = options.getString(Options.MODE, Options.LOCAL_SIGN);
        String selfSign = options.getString(Options.SELF_SIGN);
        String skipCodeSign = options.getString(Options.SKIP_CODE_SIGN, ParamConstants.SKIP_CODE_SIGN_FALSE);

        // Sign provider selection
        SignProvider signProvider;
        if (ParamConstants.SELF_SIGN_TYPE_1.equals(selfSign)) {
            // Self-sign mode
            signProvider = new SelfSignSignProvider();
            LOGGER.info("Using SelfSignSignProvider");
        } else if (ParamConstants.SKIP_CODE_SIGN_TRUE.equals(skipCodeSign)) {
            // skipCodeSign generates no code signature, no keystore/cert/signAlg is needed.
            // Reuse the keyless provider path; SignElf writes only .profile/.permission sections.
            signProvider = new SelfSignSignProvider();
            LOGGER.info("Using SelfSignSignProvider for skipCodeSign");
        } else if (Options.LOCAL_SIGN.equalsIgnoreCase(mode)) {
            // Local sign mode
            signProvider = new LocalJKSSignProvider();
            LOGGER.info("Using LocalJKSSignProvider");
        } else if (Options.REMOTE_SIGN.equalsIgnoreCase(mode)) {
            // Remote sign mode
            signProvider = new RemoteSignProvider();
            LOGGER.info("Using RemoteSignProvider");
        } else {
            LOGGER.error("Unsupported mode: {}", mode);
            return false;
        }

        // Sign ELF files
        return signProvider.signElf(options);
    }
}
