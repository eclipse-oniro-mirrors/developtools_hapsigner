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
#ifndef SIGNATURETOOLS_SIGNATRUE_TOOLS_LOG_H
#define SIGNATURETOOLS_SIGNATRUE_TOOLS_LOG_H
#include <stdio.h>
#include <iostream>
#include <time.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "signature_tools_errno.h"

namespace OHOS {
namespace SignatureTools {

static const char POINT = '.';
static const char PLACEHOLDER = '0';
static const int PLACEHOLDERLEN = 3;
static const int SCALE = 1000;

inline bool g_quietMode = false;

#define SIGNATURE_LOG_BASE(level, fmt, ...) \
    do { \
        printf("[%s] [%s] [%s] [%d] " fmt "\n", \
            level, __FILE_NAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define SIGNATURE_LOG(level, fmt, ...) \
    do { \
        if (!OHOS::SignatureTools::g_quietMode) { \
            SIGNATURE_LOG_BASE(level, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#ifdef SIGNATURE_LOG_DEBUG
#define SIGNATURE_TOOLS_LOGI(fmt, ...) SIGNATURE_LOG("Info", fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGD(fmt, ...) SIGNATURE_LOG("Debug", fmt, ##__VA_ARGS__)
#else
#define SIGNATURE_TOOLS_LOGI(fmt, ...)
#define SIGNATURE_TOOLS_LOGD(fmt, ...)
#endif

#define SIGNATURE_TOOLS_LOGW(fmt, ...) SIGNATURE_LOG("Warn", fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGF(fmt, ...) SIGNATURE_LOG_BASE("Fatal", fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGE(fmt, ...) SIGNATURE_LOG_BASE("Error", fmt, ##__VA_ARGS__)

inline std::string GetSystemTime()
{
    std::string timeBuffer;
    std::stringstream ss;
    auto now = std::chrono::system_clock::now();
    std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&nowTime);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % SCALE;
    ss << std::put_time(localTime, "%m-%d %H:%M:%S");
    ss << POINT << std::setfill(PLACEHOLDER) << std::setw(PLACEHOLDERLEN) << ms.count();
    timeBuffer = ss.str();
    return timeBuffer;
}

/*
* Function: Print the error code and error message to the terminal.
* Parametric Description: command, code, details
* command: Error code variable name as a string.
* code: Error code.
* details: Error description information.
**/
inline void PrintErrorNumberMsg(const std::string& command, const int code, const std::string& details)
{
    std::cerr << GetSystemTime() << " ERROR - " << command << ", code: "
        << code << ". Details: " << details << std::endl;
}

/*
* Function: Print a prompt to the terminal.
* Parametric Description: message
* message: Prompt Description Information.
**/
inline void PrintMsg(const std::string& message)
{
    if (g_quietMode) {
        return;
    }
    std::cout << GetSystemTime() << " INFO  - " << message << std::endl;
}

/*
 * Function: Print the final command result to stdout.
 * Parametric Description: result
 * result: Final command result.
 **/
inline void PrintResult(const std::string& result)
{
    std::cout << GetSystemTime() << " INFO  - " << result << std::endl;
}
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_SIGNATRUE_TOOLS_LOG_H