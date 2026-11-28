/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ohos.hapsigntool;

import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the parameter validation layer of {@link BinarySignTool#processCmd(String[])}.
 *
 * <p>Covers {@code CmdUtil.convert2Params} (trust list / key-value pairing / duplicate /
 * empty value / quiet validation) and {@code runSignApp} (required params, mode/selfSign/
 * skipCodeSign value validation, skipCodeSign-selfSign mutual exclusion, profile checks,
 * localSign keystore and signAlg checks).</p>
 *
 * <p>File parameters are backed by temp files created via {@link File#createTempFile}.
 * The inFile is deliberately NOT a valid ELF: validation-pass cases therefore proceed
 * into the sign workflow and fail there, so {@code processCmd} returns {@code false}
 * without throwing, which is exactly the observable "validation passed" signal.</p>
 *
 * @since 2026-11-27
 */
public class BinarySignToolTest {
    private static final String METHOD_SIGN = "sign";

    private static final String METHOD_DISPLAY_SIGN = "display-sign";

    private final List<File> tempFiles = new ArrayList<>();

    @AfterEach
    public void tearDown() {
        for (File file : tempFiles) {
            if (file.exists() && !file.delete()) {
                file.deleteOnExit();
            }
        }
        tempFiles.clear();
    }

    private File newTempFile(String prefix, String suffix, String content) throws IOException {
        File file = File.createTempFile(prefix, suffix);
        Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
        tempFiles.add(file);
        return file;
    }

    private File newInFile() throws IOException {
        // intentionally not a valid ELF image; Elfio.load rejects it gracefully
        return newTempFile("infile", ".elf", "this-is-not-an-elf-file");
    }

    private File newOutFile() throws IOException {
        return newTempFile("outfile", ".elf", "");
    }

    private File newModuleFile() throws IOException {
        return newTempFile("module", ".json", "{\"name\":\"com.example.test\",\"version\":1}");
    }

    private CustomException expectError(String[] args, ERROR expectedError, String... substrings) {
        CustomException exception = assertThrows(CustomException.class,
            () -> BinarySignTool.processCmd(args));
        assertEquals(expectedError, exception.getError());
        String message = exception.getMessage();
        for (String substring : substrings) {
            assertTrue(message.contains(substring),
                "expected message to contain <" + substring + ">, actual: " + message);
        }
        return exception;
    }

    private String[] signArgs(String... keyValues) {
        List<String> args = new ArrayList<>();
        args.add(METHOD_SIGN);
        args.addAll(Arrays.asList(keyValues));
        return args.toArray(new String[0]);
    }

    // ------------------------------------------------------------------
    // processCmd dispatch layer
    // ------------------------------------------------------------------

    @Test
    public void testNoArgsPrintsHelpAndReturnsTrue() throws Exception {
        assertTrue(BinarySignTool.processCmd(new String[0]));
    }

    @Test
    public void testHelpAndVersionFlagsReturnTrue() throws Exception {
        assertTrue(BinarySignTool.processCmd(new String[] {"-h"}));
        assertTrue(BinarySignTool.processCmd(new String[] {"-help"}));
        assertTrue(BinarySignTool.processCmd(new String[] {"-v"}));
        assertTrue(BinarySignTool.processCmd(new String[] {"-version"}));
    }

    @Test
    public void testSignWithoutAnyKeyValuePairs() {
        // args length < 2 -> PARAM_NUM_ERROR
        expectError(new String[] {METHOD_SIGN}, ERROR.COMMAND_ERROR, "Check param num failed");
    }

    @Test
    public void testUnsupportedMethod() {
        expectError(new String[] {"no-such-cmd", "-inFile", "x"},
            ERROR.COMMAND_ERROR, "Can not find method");
    }

    // ------------------------------------------------------------------
    // CmdUtil.convert2Params layer
    // ------------------------------------------------------------------

    @Test
    public void testParamNotTrusted() {
        expectError(signArgs("-noSuchParam", "v"), ERROR.COMMAND_PARAM_ERROR, "Param is not trusted");
    }

    @Test
    public void testSkipCodeSignParamIsTrusted() throws Exception {
        // before the skipCodeSign feature this param was rejected as "not trusted";
        // here it must pass the trust list and only fail later (non-ELF input)
        File inFile = newInFile();
        File outFile = newOutFile();
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            signArgs("-skipCodeSign", "true", "-inFile", inFile.getPath(), "-outFile", outFile.getPath())));
        assertFalse(result);
    }

    @Test
    public void testParamNotInPairs() {
        expectError(signArgs("inFile"), ERROR.COMMAND_PARAM_ERROR, "must in pairs");
    }

    @Test
    public void testParamValueEmpty() {
        expectError(signArgs("-inFile", ""), ERROR.COMMAND_ERROR, "value could not be empty");
    }

    @Test
    public void testParamDuplicate() {
        expectError(signArgs("-inFile", "a", "-inFile", "b"),
            ERROR.COMMAND_ERROR, "is duplicated");
    }

    @Test
    public void testQuietInvalidValue() {
        expectError(signArgs("-quiet", "yes"), ERROR.COMMAND_ERROR,
            "{quiet} param is incorrect", "value must be true/false");
    }

    // ------------------------------------------------------------------
    // runSignApp: required params / value validation / mutual exclusion
    // ------------------------------------------------------------------

    @Test
    public void testSignMissingInFile() {
        expectError(signArgs("-quiet", "false"), ERROR.COMMAND_ERROR,
            "Param {inFile} is required");
    }

    @Test
    public void testSignMissingOutFile() throws Exception {
        File inFile = newInFile();
        expectError(signArgs("-inFile", inFile.getPath()), ERROR.COMMAND_ERROR,
            "Param {outFile} is required");
    }

    @Test
    public void testSignInvalidModeValue() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        expectError(signArgs("-mode", "fooSign", "-inFile", inFile.getPath(), "-outFile", outFile.getPath()),
            ERROR.COMMAND_ERROR, "value must be localSign/remoteSign");
    }

    @Test
    public void testSignInvalidSelfSignValue() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        expectError(signArgs("-selfSign", "5", "-inFile", inFile.getPath(), "-outFile", outFile.getPath()),
            ERROR.COMMAND_ERROR, "value must be 0/1");
    }

    @Test
    public void testSignInvalidSkipCodeSignValue() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        expectError(signArgs("-skipCodeSign", "yes", "-inFile", inFile.getPath(), "-outFile", outFile.getPath()),
            ERROR.COMMAND_ERROR, "{skipCodeSign} param is incorrect", "value must be true/false");
    }

    @Test
    public void testSkipCodeSignAndSelfSignAreMutuallyExclusive() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        expectError(signArgs("-skipCodeSign", "true", "-selfSign", "1",
                "-inFile", inFile.getPath(), "-outFile", outFile.getPath()),
            ERROR.COMMAND_ERROR, "skipCodeSign and selfSign cannot be used together");
    }

    @Test
    public void testSkipCodeSignTrueDoesNotRequireSigningParams() throws Exception {
        // AC-2.1: no -mode/-keyAlias/-signAlg/-keystoreFile/-appCertFile needed;
        // validation passes, signing then fails on the non-ELF input -> false, no exception
        File inFile = newInFile();
        File outFile = newOutFile();
        File moduleFile = newModuleFile();
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            signArgs("-skipCodeSign", "true",
                "-inFile", inFile.getPath(),
                "-outFile", outFile.getPath(),
                "-moduleFile", moduleFile.getPath())));
        assertFalse(result);
    }

    @Test
    public void testSkipCodeSignFalseFollowsNormalValidation() throws Exception {
        // AC-4.2 (validation layer): skipCodeSign=false behaves like the param being absent
        File inFile = newInFile();
        File outFile = newOutFile();
        expectError(signArgs("-skipCodeSign", "false", "-inFile", inFile.getPath(), "-outFile", outFile.getPath()),
            ERROR.COMMAND_ERROR, "Param {keystoreFile} is required");
    }

    @Test
    public void testSelfSignDoesNotRequireSigningParams() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            signArgs("-selfSign", "1", "-inFile", inFile.getPath(), "-outFile", outFile.getPath())));
        assertFalse(result);
    }

    // ------------------------------------------------------------------
    // runSignApp: profile checks (exercised through the skipCodeSign branch)
    // ------------------------------------------------------------------

    @Test
    public void testSignedProfileMustBeP7b() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        File profile = newTempFile("profile", ".json", "{}");
        expectError(signArgs("-skipCodeSign", "true",
                "-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-profileFile", profile.getPath(), "-profileSigned", "1"),
            ERROR.NOT_SUPPORT_ERROR, "Not support file");
    }

    @Test
    public void testUnsignedProfileMustBeJson() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        File profile = newTempFile("profile", ".p7b", "dummy");
        expectError(signArgs("-skipCodeSign", "true",
                "-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-profileFile", profile.getPath(), "-profileSigned", "0"),
            ERROR.NOT_SUPPORT_ERROR, "Not support file");
    }

    @Test
    public void testInvalidProfileSignedValue() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        File profile = newTempFile("profile", ".p7b", "dummy");
        expectError(signArgs("-skipCodeSign", "true",
                "-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-profileFile", profile.getPath(), "-profileSigned", "2"),
            ERROR.COMMAND_ERROR, "value must be 1/0");
    }

    // ------------------------------------------------------------------
    // runSignApp: localSign keystore / signAlg checks
    // ------------------------------------------------------------------

    @Test
    public void testLocalSignMissingKeystoreParams() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        expectError(signArgs("-inFile", inFile.getPath(), "-outFile", outFile.getPath()),
            ERROR.COMMAND_ERROR, "Param {keystoreFile} is required");
    }

    @Test
    public void testLocalSignInvalidKeystoreFileType() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        File keystore = newTempFile("keystore", ".txt", "dummy");
        File appCert = newTempFile("cert", ".pem", "dummy");
        expectError(signArgs("-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-keystoreFile", keystore.getPath(), "-keyAlias", "test-key",
                "-appCertFile", appCert.getPath()),
            ERROR.NOT_SUPPORT_ERROR, "Not support file");
    }

    @Test
    public void testLocalSignMissingSignAlg() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        File keystore = newTempFile("keystore", ".p12", "dummy");
        File appCert = newTempFile("cert", ".pem", "dummy");
        expectError(signArgs("-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-keystoreFile", keystore.getPath(), "-keyAlias", "test-key",
                "-appCertFile", appCert.getPath(), "-keyPwd", "123456", "-keystorePwd", "123456"),
            ERROR.COMMAND_ERROR, "Param {signAlg} is required");
    }

    @Test
    public void testLocalSignInvalidSignAlg() throws Exception {
        File inFile = newInFile();
        File outFile = newOutFile();
        File keystore = newTempFile("keystore", ".p12", "dummy");
        File appCert = newTempFile("cert", ".pem", "dummy");
        expectError(signArgs("-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-keystoreFile", keystore.getPath(), "-keyAlias", "test-key",
                "-appCertFile", appCert.getPath(), "-keyPwd", "123456", "-keystorePwd", "123456",
                "-signAlg", "SHA256withRSA"),
            ERROR.COMMAND_ERROR, "signature algorithms include");
    }

    @Test
    public void testLocalSignFullParamsPassValidation() throws Exception {
        // all params valid -> validation passes; signing fails on non-ELF input -> false
        File inFile = newInFile();
        File outFile = newOutFile();
        File keystore = newTempFile("keystore", ".p12", "dummy");
        File appCert = newTempFile("cert", ".pem", "dummy");
        File profile = newTempFile("profile", ".p7b", "dummy");
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            signArgs("-mode", "localSign",
                "-inFile", inFile.getPath(), "-outFile", outFile.getPath(),
                "-keystoreFile", keystore.getPath(), "-keyAlias", "test-key",
                "-appCertFile", appCert.getPath(), "-keyPwd", "123456", "-keystorePwd", "123456",
                "-profileFile", profile.getPath(), "-profileSigned", "1",
                "-signAlg", "SHA256withECDSA")));
        assertFalse(result);
    }

    // ------------------------------------------------------------------
    // display-sign dispatch
    // ------------------------------------------------------------------

    @Test
    public void testDisplaySignMissingInFile() {
        expectError(new String[] {METHOD_DISPLAY_SIGN, "-quiet", "false"},
            ERROR.COMMAND_ERROR, "Param {inFile} is required");
    }

    @Test
    public void testDisplaySignNonElfReturnsFalse() throws Exception {
        File inFile = newInFile();
        // runDisplaySign catches all exceptions internally and returns false
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            new String[] {METHOD_DISPLAY_SIGN, "-inFile", inFile.getPath()}));
        assertFalse(result);
    }

    @Test
    public void testShortNonElfFileFailsGracefully() throws Exception {
        // Regression: a file shorter than the 16-byte e_ident used to escape as
        // BufferUnderflowException from Elfio.load; ElfSignContext.load now checks
        // the file length up front and must fail gracefully with false
        File inFile = newTempFile("infile", ".elf", "short");
        File outFile = newOutFile();
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            signArgs("-skipCodeSign", "true", "-inFile", inFile.getPath(), "-outFile", outFile.getPath())));
        assertFalse(result);
    }

    @Test
    public void testDisplaySignShortFileFailsGracefully() throws Exception {
        // Regression for the display-sign path: VerifyElf.verifyElf now checks the
        // file length before Elfio.load, so a file shorter than the 16-byte e_ident
        // must fail gracefully instead of throwing BufferUnderflowException
        File inFile = newTempFile("infile", ".elf", "short");
        boolean result = assertDoesNotThrow(() -> BinarySignTool.processCmd(
            new String[] {METHOD_DISPLAY_SIGN, "-inFile", inFile.getPath()}));
        assertFalse(result);
    }
}
