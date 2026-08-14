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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ohos.hapsigntool.codesigning.utils.HapUtils;
import com.ohos.hapsigntool.error.ProfileException;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link HapUtils#parsePluginId(String)}.
 *
 * @since 2026/08/21
 */
public class HapUtilsTest {
    /**
     * When app-distribution-type is developer_ID, parsePluginId returns null immediately.
     *
     * @throws ProfileException not expected
     */
    @Test
    public void testParsePluginIdDeveloperId() throws ProfileException {
        String profile = "{\"app-distribution-type\":\"developer_ID\"}";
        assertNull(HapUtils.parsePluginId(profile));
    }

    /**
     * When app-distribution-type is developer_ID, the capabilities section is not evaluated.
     *
     * @throws ProfileException not expected
     */
    @Test
    public void testParsePluginIdDeveloperIdSkipsCapabilities() throws ProfileException {
        String profile = "{\"app-distribution-type\":\"developer_ID\","
            + "\"app-services-capabilities\":{\"ohos.permission.kernel.SUPPORT_PLUGIN\":"
            + "{\"pluginDistributionIDs\":\"should-be-skipped\"}}}";
        assertNull(HapUtils.parsePluginId(profile));
    }

    /**
     * Valid profile with pluginDistributionIDs returns the plugin ID.
     *
     * @throws ProfileException not expected
     */
    @Test
    public void testParsePluginIdValid() throws ProfileException {
        String profile = "{\"app-services-capabilities\":" + "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":"
            + "{\"pluginDistributionIDs\":\"com.example.plugin\"}}}";
        assertEquals("com.example.plugin", HapUtils.parsePluginId(profile));
    }

    /**
     * When app-distribution-type is a non-developer_ID string, plugin ID is still parsed.
     *
     * @throws ProfileException not expected
     */
    @Test
    public void testParsePluginIdNonDeveloperIdDistributionType() throws ProfileException {
        String profile = "{\"app-distribution-type\":\"public\","
            + "\"app-services-capabilities\":{\"ohos.permission.kernel.SUPPORT_PLUGIN\":"
            + "{\"pluginDistributionIDs\":\"plugin123\"}}}";
        assertEquals("plugin123", HapUtils.parsePluginId(profile));
    }

    /**
     * When app-distribution-type is numeric (not a string), the developer_ID check is skipped
     * and the plugin ID is parsed from capabilities.
     *
     * @throws ProfileException not expected
     */
    @Test
    public void testParsePluginIdNumericDistributionType() throws ProfileException {
        String profile = "{\"app-distribution-type\":123,"
            + "\"app-services-capabilities\":{\"ohos.permission.kernel.SUPPORT_PLUGIN\":"
            + "{\"pluginDistributionIDs\":\"valid-plugin\"}}}";
        assertEquals("valid-plugin", HapUtils.parsePluginId(profile));
    }

    /**
     * Missing app-services-capabilities throws ProfileException.
     */
    @Test
    public void testParsePluginIdMissingCapabilities() {
        String profile = "{\"type\":\"release\"}";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }

    /**
     * Capabilities present but SUPPORT_PLUGIN permission missing throws ProfileException.
     */
    @Test
    public void testParsePluginIdMissingPermission() {
        String profile = "{\"app-services-capabilities\":{\"other.permission\":{}}}";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }

    /**
     * Permission present but pluginDistributionIDs key missing throws ProfileException.
     */
    @Test
    public void testParsePluginIdMissingPluginIdKey() {
        String profile = "{\"app-services-capabilities\":"
            + "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{\"other-key\":\"value\"}}}";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }

    /**
     * pluginDistributionIDs is numeric (not a string) throws ProfileException.
     */
    @Test
    public void testParsePluginIdValueNotString() {
        String profile = "{\"app-services-capabilities\":"
            + "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{\"pluginDistributionIDs\":12345}}}";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }

    /**
     * Empty pluginDistributionIDs throws ProfileException.
     */
    @Test
    public void testParsePluginIdEmptyValue() {
        String profile = "{\"app-services-capabilities\":"
            + "{\"ohos.permission.kernel.SUPPORT_PLUGIN\":{\"pluginDistributionIDs\":\"\"}}}";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }

    /**
     * Invalid JSON content throws ProfileException.
     */
    @Test
    public void testParsePluginIdInvalidJson() {
        String profile = "{";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }

    /**
     * JSON literal null throws ProfileException.
     */
    @Test
    public void testParsePluginIdJsonNull() {
        String profile = "null";
        assertThrows(ProfileException.class, () -> HapUtils.parsePluginId(profile));
    }
}
