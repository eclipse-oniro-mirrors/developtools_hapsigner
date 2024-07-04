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
#ifndef SIGNATRUETOOLS_FILE_UTILS_H
#define SIGNATRUETOOLS_FILE_UTILS_H
#include <string>
#include <vector>
#include <regex>
#include <cassert>
#include "thread_pool.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

class FileUtils {
public:
    static const int NUM_TWO;
    static const int NUM_THREE;
    static const int NUM_FOUR;
    /**
     * suffix regex map
     */
    static const std::unordered_map<std::string, std::regex> SUFFIX_REGEX_MAP;
    static constexpr int FILE_BUFFER_BLOCK = 1024 * 1024;
    FileUtils() = default;
    ~FileUtils() = default;
    // judge is or not empty
    static bool  IsEmpty(std::string cs);
    // get file suffix
    static  std::string GetSuffix(std::string filePath);
    // verify file type
    static bool ValidFileType(const std::string& filePath, std::initializer_list<std::string> types);
    static bool IsValidFile(std::string file);
    /**
* write content to output file
* @param content data to write
* @param output  path
* @return 0:success
*/
    static int Write(const std::string& content, const std::string& output);
    /**
* Read byte from input stream.
*
* @param input Input stream
* @param ret File content
* @return 0:success <0:error
*/
    static  int Read(std::ifstream& input, std::string& ret);
    /**
*Read byte from input file.
*
* @param file Which file to read
* @param ret  byte content
* @return 0:success <0:error
*/
    static int ReadFile(const std::string& path, std::string& ret);
    /**
     * Read byte from input file.
     *
     * @param file input file
     * @param offset offset
     * @param length length
     * @param ret data bytes
     * @return 0:success <0:error
     */
    static int ReadFileByOffsetAndLength(std::ifstream& file, size_t offset, size_t length, std::string& ret);
    /**
 * Read byte from input stream.
 *
 * @param input input stream
 * @param offset offset
 * @param length length
 * @ret data bytes
 * @return 0:success <0 :error
 */
    static int ReadInputByOffsetAndLength(std::ifstream& input, size_t offset, size_t length, std::string& ret);
    /**
 * Read byte from input stream.
 *
 * @param input InputStream
 * @param length length
 * @ret data bytes
 * @return 0:success <0 :error
 */
    static int ReadInputByLength(std::ifstream& input, size_t length, std::string& ret);
    /**
 * Write data in file to output stream
 *
 * @param inFile input file path.
 * @param out output file path.
 * @param offset file read offset
 * @param size file read size
 * @return true, if write successfully.
 */
    static bool AppendWriteFileByOffsetToFile(std::ifstream& input, std::ofstream& out, size_t offset, size_t size);
    static bool AppendWriteFileToFile(const std::string& inputFile, const std::string& outputFile);
    static bool AppendWriteByteToFile(const std::string& bytes, const std::string& outputFile);

    static int WriteInputToOutPut(std::ifstream& input, std::ofstream& output, size_t length);
    static bool WriteInputToOutPut(const std::string& input, const std::string& output);

    /**
* Write byte array data to output file.
*
* @param bytes byte array data.
* @param outFile output file path.
* @return true, if write successfully.
*/
    static bool WriteByteToOutFile(const std::string& bytes, const std::string& outFile);
    /**
* Write byte array data to output file.
*
* @param bytes byte array data.
* @param outFile output file path.
* @return true, if write successfully.
*/
    static bool WriteByteToOutFile(const std::string& bytes, std::ofstream& outFile);
    static bool WriteByteToOutFile(const std::vector<int8_t>& bytes, std::ofstream& outFile);
    /**
 * regex filename
 *
 * @param name filename
 * @return boolean
 */
    static bool IsRunnableFile(const std::string& name);
    static int64_t GetFileLen(const std::string& file);
    static void DelDir(const std::string& file);
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_FILE_UTILS_H