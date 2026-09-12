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

package com.ohos.hapsigntool.hap.sign;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.ohos.hapsigntool.codesigning.exception.CodeSignException;
import com.ohos.hapsigntool.codesigning.exception.ElfFormatException;
import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.sign.CodeSigning;
import com.ohos.hapsigntool.codesigning.utils.NumberUtils;
import com.ohos.hapsigntool.entity.ElfSignConstants;
import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.error.ModuleException;
import com.ohos.hapsigntool.error.ProfileException;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.profile.ProfileSignTool;
import com.ohos.hapsigntool.signer.ISigner;
import com.ohos.hapsigntool.utils.CompareElf;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.LogUtils;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Map;

/**
 * elf file Signature signer.
 *
 * @since 2023/11/21
 */
public class SignElf {
    private static final LogUtils LOGGER = new LogUtils(SignElf.class);

    private static final int PAGE_SIZE = 4096;

    private static final int MAX_SECTION_SIZE = 10240;

    /**
     * Constructor of Method.
     */
    public SignElf() {
    }

    private static class SigningContext {
        private final File inputFile;

        private final Path inputPath;

        private final Path outputPath;

        private final File tmpOutputFile;

        SigningContext(File inputFile, Path inputPath, Path outputPath, File tmpOutputFile) {
            this.inputFile = inputFile;
            this.inputPath = inputPath;
            this.outputPath = outputPath;
            this.tmpOutputFile = tmpOutputFile;
        }
    }

    /**
     * Sign elf file.
     *
     * @param signerConfig Config of the elf file to be signed.
     * @param signParams The input parameters of sign elf.
     * @return true if sign successfully; false otherwise.
     */
    public boolean sign(SignerConfig signerConfig, Map<String, String> signParams) {
        boolean isSuccess = false;
        File tmpOutputFile = null;
        FileChannel inputFc = null;
        try {
            SigningContext context = createSigningContext(signParams);
            if (context == null) {
                return false;
            }
            tmpOutputFile = context.tmpOutputFile;
            LOGGER.info("Start signing ELF file...");
            inputFc = FileChannel.open(context.inputFile.toPath(), StandardOpenOption.READ);
            isSuccess = executeSignWorkflow(inputFc, context, signerConfig, signParams);
        } catch (FsVerityDigestException e) {
            LOGGER.error("FsVerity digest error: {}", e.getMessage(), e);
        } catch (CodeSignException e) {
            LOGGER.error("Code sign error: {}", e.getMessage(), e);
        } catch (IOException e) {
            LOGGER.error("IO error: {}", e.getMessage(), e);
        } catch (ProfileException | ModuleException e) {
            LOGGER.error("Profile/Module error: {}", e.getMessage(), e);
        } catch (ElfFormatException e) {
            LOGGER.error("ELF process error: {}", e.getMessage(), e);
        } finally {
            if (!isSuccess && tmpOutputFile != null && tmpOutputFile.exists()) {
                try {
                    Files.deleteIfExists(tmpOutputFile.toPath());
                } catch (IOException e) {
                    LOGGER.warn("Failed to delete temp file: {}", tmpOutputFile.getPath());
                }
            }
            if (inputFc != null && inputFc.isOpen()) {
                try {
                    inputFc.close();
                } catch (IOException e) {
                    LOGGER.warn("Failed to close input file channel");
                }
            }
        }
        return isSuccess;
    }

    private SigningContext createSigningContext(Map<String, String> signParams) throws IOException {
        Path inputPath = Paths.get(signParams.get(ParamConstants.PARAM_BASIC_INPUT_FILE));
        File inputFile = inputPath.toFile();
        if (!inputFile.exists() || !inputFile.isFile()) {
            LOGGER.error("Input file does not exist or is not a file: {}", inputPath);
            return null;
        }
        Path outputPath = Paths.get(signParams.get(ParamConstants.PARAM_BASIC_OUTPUT_FILE));
        Path realInputPath = inputPath.toRealPath();
        String tmpOutputPath = (Files.exists(outputPath) && Files.isSameFile(realInputPath, outputPath)) ? realInputPath
            + "-tmp-signed" : outputPath.toString();
        return new SigningContext(inputFile, realInputPath, outputPath, new File(tmpOutputPath));
    }

    private boolean executeSignWorkflow(FileChannel inputFc, SigningContext context, SignerConfig signerConfig,
        Map<String, String> signParams)
        throws IOException, FsVerityDigestException, CodeSignException, ProfileException, ModuleException,
               ElfFormatException {
        ElfSignContext ctx = new ElfSignContext();
        if (!ctx.load(inputFc)) {
            return false;
        }
        if (inputFc.isOpen()) {
            try {
                inputFc.close();
            } catch (IOException e) {
                LOGGER.warn("Failed to close input file channel");
            }
        }
        if (!ctx.buildNewShstrtab() || !buildNewSections(ctx, signerConfig, signParams)) {
            return false;
        }
        if (!ctx.finalizeShstrtab()) {
            return false;
        }
        ElfSignWriter writer = new ElfSignWriter();
        writer.setCtx(ctx);
        long codesignOffset = writer.write(context.inputFile, context.tmpOutputFile);
        if (!new CompareElf(context.inputFile, context.tmpOutputFile).validate()) {
            LOGGER.warn("ELF file validation failed");
        }
        boolean isSelfSign = ParamConstants.SELF_SIGN_TYPE_1.equals(signParams.get(ParamConstants.PARAM_SELF_SIGN));
        byte[] codeSignBlock = generateCodeSignBlock(context.tmpOutputFile, codesignOffset, signerConfig, isSelfSign);
        if (codeSignBlock == null) {
            return false;
        }
        if (!replaceCodeSignData(context.tmpOutputFile, codesignOffset, codeSignBlock)) {
            LOGGER.error("Replace .codesign section data failed");
            return false;
        }
        return moveSignedOutput(context);
    }

    private boolean buildNewSections(ElfSignContext ctx, SignerConfig signerConfig, Map<String, String> signParams)
        throws ProfileException, ModuleException {
        boolean isSelfSign = ParamConstants.SELF_SIGN_TYPE_1.equals(signParams.get(ParamConstants.PARAM_SELF_SIGN));
        if (!isSelfSign) {
            byte[] p7b = loadProfileAndSign(signerConfig, signParams);
            if (p7b == null) {
                return false;
            }
            if (p7b.length > 0) {
                if (p7b.length > MAX_SECTION_SIZE) {
                    LOGGER.error("Profile content size exceeds maximum allowed section size (10kB)");
                    return false;
                }
                ctx.addSignSection(ElfSignConstants.PROFILE_SEC_NAME, 1, p7b);
            }
            byte[] moduleContent = loadModule(signParams);
            if (moduleContent == null) {
                return false;
            }
            if (moduleContent.length > 0) {
                String processed = writePermissionVersion(new String(moduleContent, StandardCharsets.UTF_8));
                if (processed == null) {
                    return false;
                }
                byte[] permData = processed.getBytes(StandardCharsets.UTF_8);
                ctx.addSignSection(ElfSignConstants.PERMISSION_SEC_NAME, 1, permData);
            }
        }
        byte[] placeholder = new byte[PAGE_SIZE];
        ctx.addSignSection(ElfSignConstants.CODE_SIGN_SEC_NAME, PAGE_SIZE, placeholder);
        return true;
    }

    private byte[] generateCodeSignBlock(File tmpOutputFile, long codeSignOffset, SignerConfig signerConfig,
        boolean isSelfSign) throws FsVerityDigestException, CodeSignException, IOException {
        if ((codeSignOffset <= 0) || !NumberUtils.isMultiple4K(codeSignOffset)) {
            LOGGER.error("Invalid code sign block off {}, not a multiple of 4096", codeSignOffset);
            return null;
        }
        CodeSigning codeSigning = new CodeSigning(signerConfig, isSelfSign);
        byte[] codeSignBlock = codeSigning.getElfCodeSignBlock(tmpOutputFile, codeSignOffset);
        if (codeSignBlock == null || codeSignBlock.length == 0) {
            LOGGER.error("Generate code sign block failed");
            return null;
        }
        if (codeSignBlock.length > PAGE_SIZE) {
            LOGGER.error("Code sign block size exceeds 4K: {} bytes", codeSignBlock.length);
            return null;
        }
        LOGGER.info("Generate code sign block successfully, size: {} bytes", codeSignBlock.length);
        return codeSignBlock;
    }

    private boolean moveSignedOutput(SigningContext context) throws IOException {
        Path tmpOutputFilePath = context.tmpOutputFile.toPath();
        FileUtils.copyPermissions(context.inputPath, tmpOutputFilePath);
        Path targetPath = context.outputPath.toRealPath();
        if (Files.isSameFile(tmpOutputFilePath, targetPath)) {
            return true;
        }
        try {
            Files.move(tmpOutputFilePath, targetPath, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (IOException e) {
            LOGGER.info("ATOMIC_MOVE not supported: {}, try to regular copy", e.getMessage());
        }
        Files.move(tmpOutputFilePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
        return true;
    }

    private boolean replaceCodeSignData(File outputFile, long csOffset, byte[] csData) {
        try (FileChannel fc = FileChannel.open(outputFile.toPath(), StandardOpenOption.WRITE,
            StandardOpenOption.READ)) {
            fc.position(csOffset);
            fc.write(ByteBuffer.wrap(csData));
            LOGGER.info("Replace code sign data at offset: {}, size: {}", csOffset, csData.length);
            return true;
        } catch (IOException e) {
            LOGGER.error("Replace code sign data error: {}", e.getMessage());
            return false;
        }
    }

    private byte[] loadProfileAndSign(SignerConfig signerConfig, Map<String, String> signParams)
        throws ProfileException {
        try {
            if (!signParams.containsKey(ParamConstants.PARAM_BASIC_PROFILE)) {
                LOGGER.info("No profile file provided");
                return new byte[0];
            }
            String profilePath = signParams.get(ParamConstants.PARAM_BASIC_PROFILE);
            File profileFile = new File(profilePath);
            if (!profileFile.exists() || !profileFile.isFile()) {
                LOGGER.error("Profile file does not exist: {}", profilePath);
                return null;
            }
            if (profileFile.length() > MAX_SECTION_SIZE) {
                LOGGER.error("Profile content size exceeds maximum allowed section size (10KB)");
                return null;
            }
            byte[] profileContent = Files.readAllBytes(profileFile.toPath());
            if (profileContent.length == 0) {
                LOGGER.error("Failed to read profile file or file is empty");
                return null;
            }
            String profileSigned = signParams.get(ParamConstants.PARAM_BASIC_PROFILE_SIGNED);
            if (profileSigned == null) {
                profileSigned = ParamConstants.PROFILE_SIGNED;
            }
            if (ParamConstants.PROFILE_SIGNED.equals(profileSigned)) {
                LOGGER.info("Using pre-signed profile, size: {} bytes", profileContent.length);
                return profileContent;
            }
            String signAlg = signParams.get(ParamConstants.PARAM_BASIC_SIGANTURE_ALG);
            if (signAlg == null || signAlg.isEmpty()) {
                LOGGER.error("Signature algorithm not specified for profile signing");
                return null;
            }
            ISigner signer = signerConfig.getSigner();
            if (signer == null) {
                LOGGER.error("Signer not configured for profile signing");
                return null;
            }
            byte[] signedProfile = ProfileSignTool.signProfile(profileContent, signer, signAlg);
            if (signedProfile == null || signedProfile.length == 0) {
                LOGGER.error("Failed to sign profile");
                return null;
            }
            LOGGER.info("Profile signed successfully, size: {} bytes", signedProfile.length);
            return signedProfile;
        } catch (IOException e) {
            throw new ProfileException("Load profile and sign error", e);
        }
    }

    private byte[] loadModule(Map<String, String> signParams) throws ModuleException {
        try {
            if (!signParams.containsKey(ParamConstants.PARAM_MODULE_FILE)) {
                LOGGER.info("No module file provided");
                return new byte[0];
            }
            String moduleFilePath = signParams.get(ParamConstants.PARAM_MODULE_FILE);
            File moduleFile = new File(moduleFilePath);
            if (!moduleFile.exists() || !moduleFile.isFile()) {
                LOGGER.error("Module file does not exist: {}", moduleFilePath);
                return null;
            }
            if (moduleFile.length() > MAX_SECTION_SIZE) {
                LOGGER.error("Module content size exceeds maximum allowed section size (10KB)");
                return null;
            }
            byte[] content = Files.readAllBytes(moduleFile.toPath());
            if (content == null || content.length == 0) {
                LOGGER.error("Failed to read module file or file is empty");
                return null;
            }
            LOGGER.info("Module.json file loaded, size: {} bytes", content.length);
            return content;
        } catch (IOException e) {
            throw new ModuleException("Load module error", e);
        }
    }

    private String writePermissionVersion(String moduleContent) {
        JsonObject root = JsonParser.parseString(moduleContent).getAsJsonObject();
        if (!root.has("version")) {
            root.addProperty("version", ParamConstants.PERMISSION_VERSION);
            LOGGER.info("Added version field to module.json");
        } else {
            JsonElement versionElement = root.get("version");
            if (!versionElement.isJsonPrimitive()) {
                LOGGER.error("Invalid module.json: version is not a number");
                return null;
            }
            JsonPrimitive versionPrimitive = versionElement.getAsJsonPrimitive();
            if (!versionPrimitive.isNumber()) {
                LOGGER.error("Invalid module.json: version is not a number");
                return null;
            }
            int version = versionPrimitive.getAsInt();
            if (version != ParamConstants.PERMISSION_VERSION) {
                LOGGER.error("Invalid module.json: version must be {}, but found {}", ParamConstants.PERMISSION_VERSION,
                    version);
                return null;
            }
            LOGGER.info("Module.json version validated: {}", version);
        }
        return root.toString();
    }
}
