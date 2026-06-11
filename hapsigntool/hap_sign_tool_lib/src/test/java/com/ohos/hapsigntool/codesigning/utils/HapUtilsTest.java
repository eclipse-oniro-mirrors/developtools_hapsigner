/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Unit tests for {@link HapUtils#getSkillNamesFromJson}.
 *
 * Covers the four scenarios required by spec.md AC-1/AC-2/AC-4:
 *  - TC-J-1: normal skillProfiles array
 *  - TC-J-2: empty skillProfiles array
 *  - TC-J-3: module.json without skillProfiles field
 *  - TC-J-4: invalid JSON
 *  - TC-J-5: malformed name field type is skipped, valid entries preserved
 */
class HapUtilsTest {
    @TempDir
    Path tempDir;

    private File createJarWithModuleJson(String content) throws IOException {
        File jarFile = tempDir.resolve("test.jar").toFile();
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jarFile))) {
            ZipEntry entry = new ZipEntry("module.json");
            zos.putNextEntry(entry);
            zos.write(content.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return jarFile;
    }

    @Test
    void getSkillNamesFromJson_normal_returnsAllNames() throws IOException {
        String json = "{\"module\":{\"skillProfiles\":[{\"name\":\"MySkill1\"},{\"name\":\"MySkill2\"}]}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assertions.assertEquals(2, result.size());
            Assertions.assertEquals("MySkill1", result.get(0));
            Assertions.assertEquals("MySkill2", result.get(1));
        }
    }

    @Test
    void getSkillNamesFromJson_emptyArray_returnsEmptyList() throws IOException {
        String json = "{\"module\":{\"skillProfiles\":[]}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assertions.assertTrue(result.isEmpty());
        }
    }

    @Test
    void getSkillNamesFromJson_noSkillProfilesField_returnsEmptyList() throws IOException {
        String json = "{\"module\":{}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assertions.assertTrue(result.isEmpty());
        }
    }

    @Test
    void getSkillNamesFromJson_invalidJson_returnsEmptyList() throws IOException {
        String json = "not a valid json";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assertions.assertTrue(result.isEmpty());
        }
    }

    @Test
    void getSkillNamesFromJson_malformedNameType_skipsAndPreservesValid() throws IOException {
        String json = "{\"module\":{\"skillProfiles\":["
            + "{\"name\":123},"
            + "{\"name\":true},"
            + "{\"name\":\"ValidSkill\"},"
            + "{\"name\":\"\"}"
            + "]}}";
        try (JarFile jar = new JarFile(createJarWithModuleJson(json))) {
            List<String> result = HapUtils.getSkillNamesFromJson(jar);
            Assertions.assertEquals(1, result.size());
            Assertions.assertEquals("ValidSkill", result.get(0));
        }
    }
}
