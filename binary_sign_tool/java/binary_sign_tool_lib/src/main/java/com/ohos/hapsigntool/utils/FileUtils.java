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

package com.ohos.hapsigntool.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.error.SignToolErrMsg;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Common file operation.
 *
 * @since 2021/12/28
 */
public final class FileUtils {
    /**
     * LOGGER.
     */
    private static final LogUtils LOGGER = new LogUtils(FileUtils.class);

    /**
     * add GSON static.
     */
    public static final Gson GSON = (new GsonBuilder()).disableHtmlEscaping().create();

    /**
     * File reader block size
     */
    public static final int FILE_BUFFER_BLOCK = 1024 * 1024;

    /**
     * File end
     */
    public static final int FILE_END = -1;

    /**
     * Expected split string length
     */
    public static final int SPLIT_LENGTH = 2;

    private FileUtils() {
    }

    /**
     * Close closeable quietly.
     *
     * @param closeable closeable
     */
    public static void close(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException exception) {
                LOGGER.debug(exception.getMessage(), exception);
            }
        }
    }

    /**
     * Read byte from input file.
     *
     * @param file Which file to read
     * @return byte content
     * @throws IOException Read failed
     */
    public static byte[] readFile(File file) throws IOException {
        return read(Files.newInputStream(file.toPath()));
    }

    /**
     * Read byte from input stream.
     *
     * @param input Input stream
     * @return File content
     * @throws IOException Read failed
     */
    public static byte[] read(InputStream input) throws IOException {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[FILE_BUFFER_BLOCK];
            int read;
            while ((read = input.read(buffer)) != FILE_END) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } finally {
            close(input);
        }
    }

    /**
     * Check file exist or not.
     *
     * @param filePath File path
     * @return Is file exist
     */
    public static boolean isFileExist(String filePath) {
        return new File(filePath).exists();
    }

    /**
     * Throw runtime exception if not allowed file type.
     *
     * @param filePath file path
     * @param types    Such as "txt" "json" "mp3"
     */
    public static void validFileType(String filePath, String... types) {
        String suffix = getSuffix(filePath);
        ValidateUtils.throwIfNotMatches(!StringUtils.isEmpty(suffix),
                ERROR.NOT_SUPPORT_ERROR, SignToolErrMsg.NOT_SUPPORT_FILE.toString(filePath));
        boolean isMatches = false;
        for (String type : types) {
            if (StringUtils.isEmpty(type)) {
                continue;
            }
            if (type.equalsIgnoreCase(suffix)) {
                isMatches = true;
                break;
            }
        }
        ValidateUtils.throwIfNotMatches(isMatches,
                ERROR.NOT_SUPPORT_ERROR, SignToolErrMsg.NOT_SUPPORT_FILE.toString(filePath));
    }

    /**
     * Get suffix of file.
     *
     * @param filePath file path
     * @return file suffix. Such as "txt" "json" "p12"
     */
    public static String getSuffix(String filePath) {
        if (StringUtils.isEmpty(filePath)) {
            return "";
        }
        File file = new File(filePath);
        String fileName = file.getName();
        String[] temps = fileName.split("\\.");
        if (temps.length < SPLIT_LENGTH) {
            return "";
        }
        return temps[temps.length - 1];
    }

    /**
     * Check input file is valid.
     *
     * @param file input file.
     * @throws IOException file is a directory or can't be read.
     */
    public static void isValidFile(File file) throws IOException {
        if (!file.exists()) {
            throw new FileNotFoundException("File '" + file + "' does not exist");
        }

        if (file.isDirectory()) {
            throw new IOException("File '" + file + "' exists but is a directory");
        }

        if (!file.canRead()) {
            throw new IOException("File '" + file + "' cannot be read");
        }
    }

    /**
     * Open an input stream of input file safely.
     *
     * @param file input file.
     * @return an input stream of input file
     * @throws IOException file is a directory or can't be read.
     */
    public static FileInputStream openInputStream(File file) throws IOException {
        isValidFile(file);
        return new FileInputStream(file);
    }

    /**
     * copy permission (cross-filesystem)
     */
    public static void copyPermissions(Path source, Path target) {
        //  POSIX（Linux/macOS）
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(source);
            Files.setPosixFilePermissions(target, perms);
            return;
        } catch (UnsupportedOperationException ignore) {
            // Windows
        } catch (IOException e) {
            LOGGER.warn("copy permission failed", e);
            return;
        }
        File srcFile = source.toFile();
        File dstFile = target.toFile();
        if (!dstFile.setExecutable(srcFile.canExecute()) || !dstFile.setReadable(srcFile.canRead())
            || !dstFile.setWritable(srcFile.canWrite())) {
            LOGGER.warn("set permission failed");
        }
    }
}
