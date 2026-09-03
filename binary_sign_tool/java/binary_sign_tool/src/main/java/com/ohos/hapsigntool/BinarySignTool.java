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

package com.ohos.hapsigntool;

import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.api.ServiceApi;
import com.ohos.hapsigntool.api.SignToolServiceImpl;
import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.error.InvalidParamsException;
import com.ohos.hapsigntool.error.SignToolErrMsg;
import com.ohos.hapsigntool.utils.EnterPassword;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.LogUtils;
import com.ohos.hapsigntool.utils.StringUtils;
import com.ohos.hapsigntool.cmd.CmdUtil;
import com.ohos.hapsigntool.cmd.CmdUtil.Method;
import com.ohos.hapsigntool.cmd.HelpDocument;
import com.ohos.hapsigntool.cmd.Params;

/**
 * BinarySignTool.
 *
 * @since 2021/12/28
 */
public final class BinarySignTool {
    /**
     * Add log info.
     */
    private static final LogUtils LOGGER = new LogUtils(BinarySignTool.class);

    /**
     * Tool version.
     */
    private static final String VERSION = "1.0.0";

    /**
     * Local sign.
     */
    private static final String LOCAL_SIGN = "localSign";

    /**
     * Remote sign.
     */
    private static final String REMOTE_SIGN = "remoteSign";

    /**
     * Signed.
     */
    private static final String SIGNED = "1";

    /**
     * No signed.
     */
    private static final String NOT_SIGNED = "0";

    private BinarySignTool() {
    }

    /**
     * Main entry.
     *
     * @param args arguments
     */
    public static void main(String[] args) {
        try {
            boolean isSuccess = processCmd(args);
            if (!isSuccess) {
                System.exit(1);
            }
        } catch (CustomException | InvalidParamsException e) {
            LOGGER.error(e.getMessage().trim());
            LOGGER.result(args[0] + " failed");
            System.exit(1);
        } catch (Exception e) {
            LOGGER.error(SignToolErrMsg.UNKNOWN_ERROR.toString(e.getMessage()).trim());
            LOGGER.result(args[0] + " failed");
            System.exit(1);
        }
    }

    /**
     * Process command.
     *
     * @param args arguments
     * @return command processing result
     * @throws CustomException custom exception for command execution failure
     */
    public static boolean processCmd(String[] args) throws CustomException, InvalidParamsException {
        if (args.length == 0 || StringUtils.isEmpty(args[0])) {
            help();
        } else if ("-h".equals(args[0]) || "-help".equals(args[0])) {
            help();
        } else if ("-v".equals(args[0]) || "-version".equals(args[0])) {
            version();
        } else {
            ServiceApi api = new SignToolServiceImpl();
            Params params = CmdUtil.convert2Params(args);
            LOGGER.debug(params.toString());
            LOGGER.info("Start {}", params.getMethod());
            boolean isSuccess = dispatchParams(params, api);
            LOGGER.result(String.format("%s %s", params.getMethod(), isSuccess ? "success" : "failed"));
            return isSuccess;
        }
        return true;
    }

    private static boolean dispatchParams(Params params, ServiceApi api) {
        boolean isSuccess;
        switch (params.getMethod()) {
            case Method.SIGN:
                isSuccess = runSignApp(params.getOptions(), api);
                break;
            case Method.DISPLAY_SIGN:
                isSuccess = runDisplaySign(params.getOptions(), api);
                break;
            default:
                CustomException.throwException(ERROR.COMMAND_ERROR,
                    SignToolErrMsg.UNSUPPORTED_METHOD.toString(params.getMethod()));
                isSuccess = false;
                break;
        }
        return isSuccess;
    }

    private static boolean runSignApp(Options params, ServiceApi api) {
        params.required(Options.IN_FILE, Options.OUT_FILE);
        String mode = params.getString(Options.MODE, LOCAL_SIGN);
        String selfSign = params.getString(Options.SELF_SIGN, "0");

        if (!LOCAL_SIGN.equalsIgnoreCase(mode) && !REMOTE_SIGN.equalsIgnoreCase(mode)) {
            CustomException.throwException(ERROR.COMMAND_ERROR,
                SignToolErrMsg.PARAM_CHECK_FAILED.toString(Options.MODE, "value must be localSign/remoteSign"));
        }

        if (!ParamConstants.SELF_SIGN_TYPE_1.equalsIgnoreCase(selfSign)
            && !ParamConstants.SELF_SIGN_TYPE_0.equalsIgnoreCase(selfSign)) {
            CustomException.throwException(ERROR.COMMAND_ERROR,
                SignToolErrMsg.PARAM_CHECK_FAILED.toString(Options.SELF_SIGN, "value must be 0/1"));
        }

        if (ParamConstants.SELF_SIGN_TYPE_1.equals(selfSign)) {
            return api.signHap(params);
        }

        if (LOCAL_SIGN.equalsIgnoreCase(mode)) {
            params.required(Options.KEY_STORE_FILE, Options.KEY_ALIAS, Options.APP_CERT_FILE);
            FileUtils.validFileType(params.getString(Options.KEY_STORE_FILE), "p12", "jks");
            EnterPassword.enterPassword(params);
        } else if (REMOTE_SIGN.equalsIgnoreCase(mode)) {
            checkRemoteSignParams(params);
        }
        checkProfile(params);
        params.required(Options.SIGN_ALG);
        String signAlg = params.getString(Options.SIGN_ALG);
        CmdUtil.judgeEndSignAlgType(signAlg);

        return api.signHap(params);
    }

    private static void checkRemoteSignParams(Options params) {
        params.required(Options.SIGN_SERVER, Options.SIGNER_PLUGIN, Options.ONLINE_AUTH_MODE);
        String onlineAuthMode = params.getString(Options.ONLINE_AUTH_MODE);
        if ("account".equalsIgnoreCase(onlineAuthMode)) {
            params.required(Options.USERNAME, Options.USERPWD);
        }
    }

    private static void checkProfile(Options params) {
        String profileFile = params.getString(Options.PROFILE_FILE);
        String profileSigned = params.getString(Options.PROFILE_SIGNED, SIGNED);

        if (StringUtils.isEmpty(profileFile)) {
            return;
        }
        if (!SIGNED.equals(profileSigned) && !NOT_SIGNED.equals(profileSigned)) {
            CustomException.throwException(ERROR.COMMAND_ERROR,
                SignToolErrMsg.PARAM_CHECK_FAILED.toString(Options.PROFILE_SIGNED, "value must be 1/0"));
        }
        if (SIGNED.equals(profileSigned)) {
            FileUtils.validFileType(profileFile, "p7b");
        } else {
            FileUtils.validFileType(profileFile, "json");
        }
    }

    private static boolean runDisplaySign(Options params, ServiceApi api) {
        params.required(Options.IN_FILE);

        // Call VerifyElf to display signature information
        com.ohos.hapsigntool.hap.verify.VerifyElf verifyElf = new com.ohos.hapsigntool.hap.verify.VerifyElf();
        try {
            if (!verifyElf.verify(params)) {
                LOGGER.error("display signature failed");
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.error("display signature error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Software version.
     */
    public static void version() {
        LOGGER.info(VERSION);
    }

    /**
     * Print help to console.
     */
    public static void help() {
        HelpDocument.printHelp(LOGGER);
    }
}
