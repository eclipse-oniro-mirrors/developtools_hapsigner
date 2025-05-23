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

package com.ohos.hapsigntool.error;

/**
 * ParamException.
 *
 * @since 2024/04/06
 */
public class ParamException extends Exception {
    /**
     * ParamException
     *
     * @param key key
     */
    public ParamException(String key) {
        super("param " + key + " is null");
    }

    /**
     * ParamException
     *
     * @param key key
     * @param message message
     */
    public ParamException(String key, String message) {
        super("param " + key + " " + message);
    }
}
