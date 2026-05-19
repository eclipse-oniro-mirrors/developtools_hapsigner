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
import com.ohos.elfio.ElfTypes;
import com.ohos.elfio.Elfio;
import com.ohos.elfio.Section;
import com.ohos.hapsigntool.codesigning.exception.CodeSignException;
import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.sign.CodeSigning;
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
import java.nio.channels.FileChannel;
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
    /**
     * codesign section name
     */
    private static final String CODE_SIGN_SEC_NAME = ".codesign";

    /**
     * permission section name
     */
    private static final String PERMISSION_SEC_NAME = ".permission";

    /**
     * profile section name
     */
    private static final String PROFILE_SEC_NAME = ".profile";

    private static final LogUtils LOGGER = new LogUtils(SignElf.class);

    private static final int PAGE_SIZE = 4096;

    private static final int MAX_SECTION_SIZE = 10240;

    private FileChannel inputFc;

    /**
     * Constructor of Method
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
     * 1. Load ELF file and remove existing signature sections
     * 2. Write profile and permission sections (if needed)
     * 3. Add .codesign section placeholder (4K aligned)
     * 4. Generate code sign block
     * 5. Replace .codesign section data
     *
     * @param signerConfig Config of the elf file to be signed.
     * @param signParams The input parameters of sign elf.
     * @return true if sign successfully; false otherwise.
     */
    public boolean sign(SignerConfig signerConfig, Map<String, String> signParams) {
        boolean isSuccess = false;
        File tmpOutputFile = null;
        try {
            SigningContext context = createSigningContext(signParams);
            if (context == null) {
                return false;
            }
            tmpOutputFile = context.tmpOutputFile;
            LOGGER.info("Start signing ELF file...");
            isSuccess = executeSignWorkflow(context, signerConfig, signParams);
        } catch (FsVerityDigestException e) {
            LOGGER.error("FsVerity digest error: {}", e.getMessage(), e);
        } catch (CodeSignException e) {
            LOGGER.error("Code sign error: {}", e.getMessage(), e);
        } catch (IOException e) {
            LOGGER.error("IO error: {}", e.getMessage(), e);
        } catch (ProfileException | ModuleException e) {
            LOGGER.error("Profile/Module error: {}", e.getMessage(), e);
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
        String tmpOutputPath = (Files.exists(outputPath) && Files.isSameFile(inputPath, outputPath))
            ? inputPath + "-tmp-signed"
            : outputPath.toString();
        return new SigningContext(inputFile, inputPath, outputPath, new File(tmpOutputPath));
    }

    private boolean executeSignWorkflow(SigningContext context, SignerConfig signerConfig,
        Map<String, String> signParams)
        throws IOException, FsVerityDigestException, CodeSignException, ProfileException, ModuleException {
        inputFc = FileChannel.open(context.inputFile.toPath(), StandardOpenOption.READ);
        Elfio elfio = new Elfio();
        if (!elfio.load(inputFc, true)) {
            LOGGER.error("Failed to load ELF file: {}", context.inputPath);
            return false;
        }
        if (!removeSignatureSections(elfio) || !writeOptionalSections(elfio, signerConfig, signParams)) {
            return false;
        }
        long codeSignOffset = createCodeSignSectionAndSave(elfio, context.tmpOutputFile);
        if (codeSignOffset < 0) {
            return false;
        }
        // Validate the saved ELF file against original elfio before generating code signature
        if (!new CompareElf(context.inputFile, context.tmpOutputFile).validate()) {
            LOGGER.warn("ELF file validation failed");
        }
        String selfSign = signParams.get(ParamConstants.PARAM_SELF_SIGN);
        boolean isSelfSign = ParamConstants.SELF_SIGN_TYPE_1.equals(selfSign);
        byte[] codeSignBlock = generateCodeSignBlock(context.tmpOutputFile, codeSignOffset, signerConfig, isSelfSign);
        if (codeSignBlock == null) {
            return false;
        }
        if (!replaceCodeSignData(context.tmpOutputFile, codeSignOffset, codeSignBlock)) {
            LOGGER.error("Replace .codesign section data failed");
            return false;
        }
        return moveSignedOutput(context);
    }

    private boolean removeSignatureSections(Elfio elfio) {
        if (!removeSection(elfio, CODE_SIGN_SEC_NAME)) {
            LOGGER.error("Failed to remove existing .codesign section");
            return false;
        }
        if (!removeSection(elfio, PERMISSION_SEC_NAME)) {
            LOGGER.error("Failed to remove existing .permission section");
            return false;
        }
        if (!removeSection(elfio, PROFILE_SEC_NAME)) {
            LOGGER.error("Failed to remove existing .profile section");
            return false;
        }
        return true;
    }

    private boolean writeOptionalSections(Elfio elfio, SignerConfig signerConfig,
        Map<String, String> signParams) throws ProfileException, ModuleException {
        String selfSign = signParams.get(ParamConstants.PARAM_SELF_SIGN);
        boolean isSelfSign = ParamConstants.SELF_SIGN_TYPE_1.equals(selfSign);
        if (isSelfSign) {
            LOGGER.info("Self-sign mode enabled, skip writing .profile and .permission sections");
            return true;
        }
        return writeSectionData(elfio, signerConfig, signParams);
    }

    private long createCodeSignSectionAndSave(Elfio elfio, File tmpOutputFile) throws IOException {
        if (!writeCodeSignBlock(elfio)) {
            LOGGER.error("Write .codesign section placeholder failed");
            return -1;
        }
        Section codeSignSection = elfio.getSection(CODE_SIGN_SEC_NAME);
        if (codeSignSection == null) {
            LOGGER.error("Failed to get .codesign section");
            return -1;
        }
        if (!elfio.save(tmpOutputFile.getPath())) {
            LOGGER.error("Failed to save ELF file to temp path: {}", tmpOutputFile.getPath());
            return -1;
        }
        return codeSignSection.getOffset();
    }

    private byte[] generateCodeSignBlock(File tmpOutputFile, long codeSignOffset, SignerConfig signerConfig,
        boolean isSelfSign) throws FsVerityDigestException, CodeSignException, IOException, ProfileException {
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
            LOGGER.info("ATOMIC_MOVE not supported : {}", e.getMessage());
        }
        Files.move(tmpOutputFilePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
        return true;
    }

    /**
     * Write profile and permission sections to ELF file
     *
     * @param elfio ELF file object
     * @param signerConfig Signer configuration
     * @param signParams Sign parameters
     * @return true if success
     */
    private boolean writeSectionData(Elfio elfio, SignerConfig signerConfig, Map<String, String> signParams)
        throws ProfileException, ModuleException {
        // Step 1: Load and sign profile if needed
        byte[] p7b = loadProfileAndSign(elfio, signerConfig, signParams);
        if (p7b == null) {
            return false;
        } else if (p7b.length > 0) {
            // Check size limit
            if (p7b.length > MAX_SECTION_SIZE) {
                LOGGER.error("Profile content size exceeds maximum allowed section size (10kB)");
                return false;
            }

            // Write profile section to ELF file
            if (!addSection(elfio, PROFILE_SEC_NAME, p7b)) {
                LOGGER.error("Failed to add .profile section");
                return false;
            }
            LOGGER.info("Added .profile section, size: {} bytes", p7b.length);
        }

        // Step 2: Load module.json file
        byte[] moduleContent = loadModule(signParams);
        if (moduleContent == null) {
            return false;
        } else if (moduleContent.length > 0) {
            // Step 3: Validate/set permission version
            String moduleJson = new String(moduleContent, java.nio.charset.StandardCharsets.UTF_8);
            String processedModule = writePermissionVersion(moduleJson);

            if (processedModule == null) {
                LOGGER.error("Failed to validate/set permission version");
                return false;
            }

            // Convert back to bytes
            byte[] permissionContent = processedModule.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            // Write permission section to ELF file
            if (!addSection(elfio, PERMISSION_SEC_NAME, permissionContent)) {
                LOGGER.error("Failed to add .permission section");
                return false;
            }
            LOGGER.info("Added .permission section, size: {} bytes", permissionContent.length);
        }

        return true;
    }

    /**
     * Write .codesign section placeholder (4K aligned)
     *
     * @param elfio ELF file object
     * @return true if success
     */
    private boolean writeCodeSignBlock(Elfio elfio) {
        // Check if .codesign section already exists
        if (elfio.getSection(CODE_SIGN_SEC_NAME) != null) {
            LOGGER.error(".codesign section already exists");
            return false;
        }

        // Add .codesign section
        Section section = elfio.addSection(CODE_SIGN_SEC_NAME);
        if (section == null) {
            LOGGER.error("Failed to create .codesign section");
            return false;
        }

        // Set section properties
        section.setType(ElfTypes.SHT_PROGBITS);
        section.setAddrAlign(PAGE_SIZE);

        // Write 4KB placeholder data
        byte[] placeholder = new byte[PAGE_SIZE];
        section.setData(placeholder);

        LOGGER.info("Added .codesign section placeholder, offset: {}, size: {} bytes", section.getOffset(), PAGE_SIZE);
        return true;
    }

    /**
     * Replace code sign data at specified offset
     *
     * @param outputFile Output file
     * @param csOffset Code sign section offset
     * @param csData Code sign data
     * @return true if success
     */
    private boolean replaceCodeSignData(File outputFile, long csOffset, byte[] csData) {
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(outputFile, "rw")) {
            // Seek to code sign section offset
            raf.seek(csOffset);

            // Write code sign data
            raf.write(csData);

            LOGGER.info("Replace code sign data at offset: {}, size: {}", csOffset, csData.length);
            return true;
        } catch (IOException e) {
            LOGGER.error("Replace code sign data error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Load profile file and sign it if needed
     *
     * @param elfio ELF file object
     * @param signerConfig Signer configuration
     * @param signParams Sign parameters
     * @return signed profile data, or null if failed
     */
    private byte[] loadProfileAndSign(Elfio elfio, SignerConfig signerConfig, Map<String, String> signParams)
        throws ProfileException {
        try {
            // If no profile file provided, return null (no profile needed)
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

            // Check size limit
            if (profileFile.length() > MAX_SECTION_SIZE) {
                LOGGER.error("Profile content size exceeds maximum allowed section size (10KB)");
                return null;
            }

            byte[] profileContent = Files.readAllBytes(profileFile.toPath());
            if (profileContent.length == 0) {
                LOGGER.error("Failed to read profile file or file is empty");
                return null;
            }

            // Check if profile is already signed
            String profileSigned = signParams.get(ParamConstants.PARAM_BASIC_PROFILE_SIGNED);
            if (profileSigned == null) {
                // Default: profile is already signed
                profileSigned = ParamConstants.PROFILE_SIGNED;
            }

            if (ParamConstants.PROFILE_SIGNED.equals(profileSigned)) {
                // Profile is already signed, use as-is
                LOGGER.info("Using pre-signed profile, size: {} bytes", profileContent.length);
                return profileContent;
            }
            // Profile needs to be signed
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
            throw new ProfileException("Load profile and sign error",e);
        }
    }

    /**
     * Load module.json file
     *
     * @param signParams Sign parameters
     * @return module content, or null if failed
     */
    private byte[] loadModule(Map<String, String> signParams) throws ModuleException {
        try {
            // If no module file provided, return null
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

            // Check size limit
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
            throw new ModuleException("Load module error",e);
        }
    }

    /**
     * Write permission version to module.json content
     * Uses Gson library for JSON parsing
     *
     * @param moduleContent Original module.json content
     * @return Processed content with version validated/set, or null if failed
     */
    private String writePermissionVersion(String moduleContent) {
        // Parse JSON using Gson (equivalent to cJSON_Parse in C++)
        JsonObject root = JsonParser.parseString(moduleContent).getAsJsonObject();

        if (!root.has("version")) {
            // Version field doesn't exist, add it
            root.addProperty("version", ParamConstants.PERMISSION_VERSION);
            LOGGER.info("Added version field to module.json");
        } else {
            // Version field exists, validate it
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

        // Return unformatted JSON (equivalent to cJSON_PrintUnformatted in C++)
        return root.toString();
    }

    /**
     * Remove a section from ELF file.
     * Removes the last section with the specified name.
     *
     * @param elfio ELF file object
     * @param sectionName Name of section to remove
     * @return true if success
     */
    private boolean removeSection(Elfio elfio, String sectionName) {
        Section section = elfio.getSection(sectionName);
        if (section == null) {
            return true;
        }
        boolean removed = elfio.removeLastSection(sectionName);
        if (removed) {
            LOGGER.info("Removed section: {}", sectionName);
        }
        return removed;
    }

    /**
     * Add a section to ELF file with data.
     *
     * @param elfio ELF file object
     * @param sectionName Name of section to add
     * @param content Section data content
     * @return true if success
     */
    private boolean addSection(Elfio elfio, String sectionName, byte[] content) {
        // Check if section already exists
        if (elfio.getSection(sectionName) != null) {
            LOGGER.error("Section {} already exists", sectionName);
            return false;
        }

        // Add section
        Section section = elfio.addSection(sectionName);
        if (section == null) {
            LOGGER.error("Failed to create section {}", sectionName);
            return false;
        }

        // Set section properties
        section.setType(ElfTypes.SHT_PROGBITS);
        section.setAddrAlign(1);
        section.setData(content);

        LOGGER.info("Added section {}, size: {} bytes", sectionName, content.length);
        return true;
    }
}
