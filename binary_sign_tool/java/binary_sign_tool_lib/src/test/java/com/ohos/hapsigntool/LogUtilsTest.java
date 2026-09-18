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

import com.ohos.hapsigntool.utils.LogUtils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * Test print logs.
 *
 * @since 2025/07/24
 */
public class LogUtilsTest {
    private static final LogUtils LOGGER = new LogUtils(LogUtilsTest.class);

    private static final String NORMAL_CHARACTER = "test 123ABC";
    private static final String SPECIAL_CHARACTER = "$#./\\%@,:;*+=|?<>!~`-_\"'()[]{}";

    /**
     * Test print debug logs.
     */
    @Test
    public void testPrintDebugLog() {
        LOGGER.debug(null);
        LOGGER.debug(NORMAL_CHARACTER);
        LOGGER.debug(SPECIAL_CHARACTER);
        LOGGER.debug("arg1: {}", null);
        LOGGER.debug("arg1: {}", NORMAL_CHARACTER);
        LOGGER.debug("arg1: {}", SPECIAL_CHARACTER);
        LOGGER.debug("arg1: {}, arg2: {}", NORMAL_CHARACTER, null);
        LOGGER.debug("arg1: {}, arg2: {}", SPECIAL_CHARACTER, null);
        LOGGER.debug("arg1: {}, arg2: {}", null, NORMAL_CHARACTER);
        LOGGER.debug("arg1: {}, arg2: {}", null, SPECIAL_CHARACTER);
        LOGGER.debug("arg1: {}, arg2: {}", null, null);
        LOGGER.debug("arg1: {}, arg2: {}", NORMAL_CHARACTER, SPECIAL_CHARACTER);
        LOGGER.debug("arg1: {}, arg2: {}", SPECIAL_CHARACTER, NORMAL_CHARACTER);
    }

    /**
     * Test print info logs.
     */
    @Test
    public void testPrintInfoLog() {
        LOGGER.info(null);
        LOGGER.info(NORMAL_CHARACTER);
        LOGGER.info(SPECIAL_CHARACTER);
        LOGGER.info("arg1: {}", null);
        LOGGER.info("arg1: {}", NORMAL_CHARACTER);
        LOGGER.info("arg1: {}", SPECIAL_CHARACTER);
        LOGGER.info("arg1: {}, arg2: {}", NORMAL_CHARACTER, null);
        LOGGER.info("arg1: {}, arg2: {}", SPECIAL_CHARACTER, null);
        LOGGER.info("arg1: {}, arg2: {}", null, NORMAL_CHARACTER);
        LOGGER.info("arg1: {}, arg2: {}", null, SPECIAL_CHARACTER);
        LOGGER.info("arg1: {}, arg2: {}", null, null);
        LOGGER.info("arg1: {}, arg2: {}", NORMAL_CHARACTER, SPECIAL_CHARACTER);
        LOGGER.info("arg1: {}, arg2: {}", SPECIAL_CHARACTER, NORMAL_CHARACTER);
    }

    /**
     * Test print warn logs.
     */
    @Test
    public void testPrintWarnLog() {
        LOGGER.warn(null);
        LOGGER.warn(NORMAL_CHARACTER);
        LOGGER.warn(SPECIAL_CHARACTER);
        LOGGER.warn("arg1: {}", null);
        LOGGER.warn("arg1: {}", NORMAL_CHARACTER);
        LOGGER.warn("arg1: {}", SPECIAL_CHARACTER);
        LOGGER.warn("arg1: {}, arg2: {}", NORMAL_CHARACTER, null);
        LOGGER.warn("arg1: {}, arg2: {}", SPECIAL_CHARACTER, null);
        LOGGER.warn("arg1: {}, arg2: {}", null, NORMAL_CHARACTER);
        LOGGER.warn("arg1: {}, arg2: {}", null, SPECIAL_CHARACTER);
        LOGGER.warn("arg1: {}, arg2: {}", null, null);
        LOGGER.warn("arg1: {}, arg2: {}", NORMAL_CHARACTER, SPECIAL_CHARACTER);
        LOGGER.warn("arg1: {}, arg2: {}", SPECIAL_CHARACTER, NORMAL_CHARACTER);
    }

    /**
     * Test print error logs.
     */
    @Test
    public void testPrintErrorLog() {
        LOGGER.error(null);
        LOGGER.error(NORMAL_CHARACTER);
        LOGGER.error(SPECIAL_CHARACTER);
        LOGGER.error("arg1: {}", null);
        LOGGER.error("arg1: {}", NORMAL_CHARACTER);
        LOGGER.error("arg1: {}", SPECIAL_CHARACTER);
        LOGGER.error("arg1: {}, arg2: {}", NORMAL_CHARACTER, null);
        LOGGER.error("arg1: {}, arg2: {}", SPECIAL_CHARACTER, null);
        LOGGER.error("arg1: {}, arg2: {}", null, NORMAL_CHARACTER);
        LOGGER.error("arg1: {}, arg2: {}", null, SPECIAL_CHARACTER);
        LOGGER.error("arg1: {}, arg2: {}", null, null);
        LOGGER.error("arg1: {}, arg2: {}", NORMAL_CHARACTER, SPECIAL_CHARACTER);
        LOGGER.error("arg1: {}, arg2: {}", SPECIAL_CHARACTER, NORMAL_CHARACTER);
    }

    /**
     * Test result is printed in quiet mode.
     */
    @Test
    public void testPrintQuietResult() {
        PrintStream originalOut = System.out;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(output));
            LogUtils.setQuiet(true);
            LOGGER.result("sign success");
            Assertions.assertTrue(new String(output.toByteArray(), StandardCharsets.UTF_8)
                .matches("\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}  INFO - sign success"
                    + System.lineSeparator()));
        } finally {
            LogUtils.setQuiet(false);
            System.setOut(originalOut);
        }
    }
}
