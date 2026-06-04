/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "file_utils.h"
#include <chrono>
#include <climits>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include "string_utils.h"
#include "signature_tools_errno.h"

namespace OHOS {
namespace SignatureTools {

const int FileUtils::NUM_TWO = 2;
const int FileUtils::NUM_THREE = 3;
const int FileUtils::NUM_FOUR = 4;
const std::string FileUtils::LIBS_PATH_PREFIX = "libs/";
const char ELF_MAGIC[] = { '\x7f', 'E', 'L', 'F' };
bool FileUtils::IsEmpty(std::string cs)
{
    if (cs.length() == 0) {
        return true;
    }
    return false;
}

std::string FileUtils::GetSuffix(std::string filePath)
{
    if (filePath.empty()) {
        return "";
    }
    size_t lastDotPosition = filePath.rfind(".");
    bool positionFlag = (lastDotPosition == std::string::npos) || (lastDotPosition == filePath.size() - 1);
    if (positionFlag) {
        return "";
    }
    return filePath.substr(lastDotPosition + 1);
}

std::string FileUtils::GetParentPath(const std::string &path)
{
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash == 0) {
        return "/";
    }
    if (lastSlash == std::string::npos) {
        return "";
    }

    return path.substr(0, lastSlash);
}

std::string FileUtils::GetFileName(const std::string &path)
{
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash == std::string::npos) {
        return path;
    }

    return path.substr(lastSlash + 1);
}

bool FileUtils::ValidFileType(const std::string& filePath, const std::initializer_list<std::string> types)
{
    std::string suffix = GetSuffix(filePath);
    bool flag = suffix.empty() || (StringUtils::ContainsCase(types, suffix) == false);
    if (flag) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "Not support file: " + filePath);
        return false;
    }
    return true;
}

int FileUtils::Write(const std::string& content, const std::string& output)
{
    std::ofstream outFile(output, std::ios::binary);
    bool flag = (outFile.rdstate() != 0);
    if (flag) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open output file: " + output + " failed");
        return IO_ERROR;
    }
    outFile.write(&content[0], content.size());
    if (outFile.rdstate() != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "Failed to write data to output stream.");
        return IO_ERROR;
    }
    return RET_OK;
}

int FileUtils::Read(std::ifstream& input, std::string& ret)
{
    ret.clear();
    if (input.rdstate() != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "invalid input stream");
        return IO_ERROR;
    }
    ret.clear();
    std::string buffer(FileUtils::FILE_BUFFER_BLOCK, 0);
    while (input) {
        input.read(&buffer[0], buffer.size());
        if (input.fail() && !input.eof()) {
            SIGNATURE_TOOLS_LOGE("error occurred while reading data");
            return IO_ERROR;
        }
        ret.append(&buffer[0], input.gcount());
    }
    return RET_OK;
}

int FileUtils::ReadFile(const std::string& path, std::string& ret)
{
    std::ifstream file(path, std::ios::binary);
    bool flag = (file.rdstate() != 0);
    if (flag) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open input file: " + path + " failed");
        return IO_ERROR;
    }
    if (Read(file, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("read error!");
        return IO_ERROR;
    }
    return RET_OK;
}

bool FileUtils::ReadFileToByteBuffer(const std::string& file, ByteBuffer& buffer)
{
    std::string ret;
    if (ReadFile(file, ret) < 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, file + " not exist or can not read!");
        return false;
    }
    buffer.SetCapacity(static_cast<int32_t>(ret.size()));
    buffer.PutData(ret.data(), ret.size());
    return true;
}

bool FileUtils::isElfFile(const std::string& filePath)
{
    char magic[sizeof(ELF_MAGIC)];
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open input file: " + filePath + " failed");
        return false;
    }
    file.read(magic, sizeof(ELF_MAGIC));
    return std::equal(magic, magic + sizeof(ELF_MAGIC), ELF_MAGIC);
}

int FileUtils::ReadFileByOffsetAndLength(std::ifstream& file, size_t offset, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Size cannot be greater than Integer max value: %zu", length);
        return RET_FAILED;
    }
    if (ReadInputByOffsetAndLength(file, offset, length, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("Error readInputByOffsetAndLength");
        return IO_ERROR;
    }
    return RET_OK;
}

int FileUtils::ReadInputByOffsetAndLength(std::ifstream& input, size_t offset, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Size cannot be greater than Integer max value: %zu", length);
        return -1;
    }
    input.seekg(offset);
    if (ReadInputByLength(input, length, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("Error readInputByLength");
        return -1;
    }
    return RET_OK;
}

int FileUtils::ReadInputByLength(std::ifstream& input, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Size cannot be greater than Integer max value: %zu", length);
        return -1;
    }
    if (input.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Error input");
        return -1;
    }
    ret.clear();

    char* buffer = new (std::nothrow)char[FILE_BUFFER_BLOCK];
    if (buffer == NULL) {
        SIGNATURE_TOOLS_LOGE("create buffer error!");
        return -1;
    }
    size_t hasReadLen = 0;

    while (hasReadLen < length && input) {
        int readLen = static_cast<int>(std::min(length - hasReadLen, (size_t)FILE_BUFFER_BLOCK));
        input.read(buffer, readLen);
        bool flag = (input.gcount() != readLen);
        if (flag) {
            delete[] buffer;
            SIGNATURE_TOOLS_LOGE("read %zu bytes data less than %zu", hasReadLen, length);
            return -1;
        }
        ret.append(buffer, readLen);
        hasReadLen += readLen;
    }
    delete[] buffer;
    if (hasReadLen != length) {
        SIGNATURE_TOOLS_LOGE("read %zu bytes data less than %zu", hasReadLen, length);
        return -1;
    }
    return RET_OK;
}

int FileUtils::WriteInputToOutPut(std::ifstream& input, std::ofstream& output, size_t length)
{
    int result = RET_OK;
    char* buf = new (std::nothrow)char[FILE_BUFFER_BLOCK];
    if (buf == NULL) {
        SIGNATURE_TOOLS_LOGE("create buffer error!");
        return RET_FAILED;
    }

    while (input) {
        int min = std::min(static_cast<int>(length), FILE_BUFFER_BLOCK);
        input.read(buf, min);
        if (input.fail() && !input.eof()) {
            SIGNATURE_TOOLS_LOGE("read error!");
            delete[] buf;
            return IO_ERROR;
        }
        length -= input.gcount();
        output.write(buf, input.gcount());
        if (!output.good()) {
            SIGNATURE_TOOLS_LOGE("write error!");
            delete[] buf;
            return IO_ERROR;
        }

        if (length <= 0) {
            break;
        }
    }
    delete[] buf;
    // After the file is written, datasize must be 0, so the if condition will never hold
    if (length != 0) {
        SIGNATURE_TOOLS_LOGE("written length error!");
        return IO_ERROR;
    }
    return result;
}

bool FileUtils::WriteInputToOutPut(const std::string& input, const std::string& output)
{
    std::ifstream in(input, std::ios::binary);
    std::ofstream out(output, std::ios::binary);
    bool flag = (in.rdstate() != 0);
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to get input stream object!");
        return false;
    }
    flag = (out.rdstate() != 0);
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to get output stream object!");
        return false;
    }
    char* buffer = new char[FILE_BUFFER_BLOCK];
    while (!in.eof()) {
        in.read(buffer, FILE_BUFFER_BLOCK);

        if (in.fail() && !in.eof()) {
            SIGNATURE_TOOLS_LOGE("error occurred while reading data");
            delete[]buffer;
            return false;
        }

        std::streamsize readLen = in.gcount();
        if (readLen > 0) {
            out.write(buffer, readLen);
        }

        if (!out) {
            SIGNATURE_TOOLS_LOGE("error occurred while writing data");
            delete[]buffer;
            return false;
        }
    }
    delete[]buffer;
    return true;
}

bool FileUtils::IsRunnableFile(const std::string& name)
{
    if (name.empty()) {
        return false;
    }
    size_t dotPos = name.rfind('.');
    if (dotPos == std::string::npos) {
        return false;
    }
    std::string suffix = name.substr(dotPos + 1);
    if (suffix == "an" || suffix == "abc") {
        return true;
    }
    std::string libDir = name.substr(0, LIBS_PATH_PREFIX.size());
    if (LIBS_PATH_PREFIX.compare(libDir) == 0) {
        return true;
    }
    return false;
}

bool FileUtils::IsValidFile(std::string file)
{
    struct stat fileStat;
    bool flag = (stat(file.c_str(), &fileStat) == 0);
    if (!flag) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "'" + file + "' file is not exists");
        return false;
    }
    flag = S_ISDIR(fileStat.st_mode);
    if (flag) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "'" + file + "' file is a directory not file");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("IsValidFile check pass %s", file.c_str());
    return true;
}

bool FileUtils::CopyTmpFileAndDel(const std::string& tmpFile, const std::string& output)
{
    if (tmpFile == output) {
        return true;
    }

    char realOutputBuf[PATH_MAX + 1] = {0};
    std::string targetPath = output;
    if (realpath(output.c_str(), realOutputBuf) != nullptr) {
        targetPath = realOutputBuf;
    }

    if (rename(tmpFile.c_str(), targetPath.c_str()) == 0) {
        SIGNATURE_TOOLS_LOGI("CopyTmpFileAndDel rename success");
        return true;
    }
    SIGNATURE_TOOLS_LOGI("rename failed, errno=%d(%s), fall back to stream copy", errno, strerror(errno));

    std::ifstream src(tmpFile, std::ios::binary);
    if (!src) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "'" + tmpFile + "' open failed");
        return false;
    }
    std::ofstream dst(targetPath, std::ios::binary | std::ios::trunc);
    if (!dst) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "'" + targetPath + "' open failed");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("CopyTmpFileAndDel stream copy");
    dst << src.rdbuf();
    if (!dst || !src) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "Failed to copy file from '"
                            + tmpFile + "' to '" + targetPath + "'");
        return false;
    }
    if (unlink(tmpFile.c_str()) != 0) {
        SIGNATURE_TOOLS_LOGE("Error: remove tmpFile");
    }
    SIGNATURE_TOOLS_LOGI("CopyTmpFileAndDel finish");
    return true;
}

void FileUtils::CopyPermissions(const std::string& srcFile, const std::string& dstFile)
{
    struct stat srcStat;
    if (stat(srcFile.c_str(), &srcStat) != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to stat source file: %s", srcFile.c_str());
        return;
    }
    if (chmod(dstFile.c_str(), srcStat.st_mode) != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to chmod destination file: %s", dstFile.c_str());
        return;
    }
    SIGNATURE_TOOLS_LOGI("CopyPermissions from %s to %s, mode: %o", srcFile.c_str(), dstFile.c_str(), srcStat.st_mode);
}

bool FileUtils::IsSameFile(const std::string& file1, const std::string& file2)
{
    struct stat stat1;
    struct stat stat2;
    if (stat(file1.c_str(), &stat1) != 0 || stat(file2.c_str(), &stat2) != 0) {
        return false;
    }
    return stat1.st_dev == stat2.st_dev && stat1.st_ino == stat2.st_ino;
}
} // namespace SignatureTools
} // namespace OHOS