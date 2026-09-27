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
#include "ticket_staple.h"
#include <algorithm>

#include "signature_tools_errno.h"
#include "signature_tools_log.h"
#include "constant.h"
#include "hap_signer_block_utils.h"
#include "hap_utils.h"
#include "zip_utils.h"
#include "pkcs7_data.h"

namespace OHOS {
namespace SignatureTools {

bool TicketStaple::CopyFileRange(RandomAccessFile& inputFile, std::ofstream& output,
    int64_t offset, int64_t size, const std::string& errMsg)
{
    static constexpr int64_t fileCopyChunkSize = 4096;
    while (size > 0) {
        int64_t readSize = std::min(fileCopyChunkSize, size);
        ByteBuffer chunkBuffer(static_cast<int32_t>(readSize));
        int32_t readRet = inputFile.ReadFileFullyFromOffset(chunkBuffer, offset);
        if (readRet < 0) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR, errMsg);
            return false;
        }
        output.write(chunkBuffer.GetBufferPtr(), readSize);
        offset += readSize;
        size -= readSize;
    }
    return true;
}

bool TicketStaple::ReadZip64Eocd(RandomAccessFile& inputFile, int64_t eocdOffset,
    StapleContext& ctx)
{
    Zip64EndOfCentralDirectoryLocator locator;
    if (!HapSignerBlockUtils::FindZip64EocdLocator(inputFile, eocdOffset, locator)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "find zip64 eocd locator failed");
        return false;
    }
    ctx.zip64Locator = locator;
    ByteBuffer zip64EocdBuffer(Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH);
    if (inputFile.ReadFileFullyFromOffset(zip64EocdBuffer,
        static_cast<int64_t>(locator.GetZip64EocdOffset())) < 0) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "read zip64 eocd failed");
        return false;
    }
    std::string zip64EocdStr(zip64EocdBuffer.GetBufferPtr(), zip64EocdBuffer.GetLimit());
    auto parsed = Zip64EndOfCentralDirectory::GetByBytes(zip64EocdStr);
    if (!parsed) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "parse zip64 eocd failed");
        return false;
    }
    ctx.zip64Eocd = parsed.value();
    return true;
}

bool TicketStaple::ExtractStapleInfo(const std::string& inFile, StapleContext& ctx)
{
    RandomAccessFile inputFile;
    if (!inputFile.Init(inFile)) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open input file failed: " + inFile);
        return false;
    }
    if (!HapSignerBlockUtils::FindHapSignature(inputFile, ctx.signInfo)) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "find HAP signature failed");
        return false;
    }
    int64_t signingBlockSize = ctx.signInfo.hapCentralDirOffset -
        ctx.signInfo.hapSigningBlockOffset;
    ctx.originalSigningBlock.SetCapacity(static_cast<int32_t>(signingBlockSize));
    if (inputFile.ReadFileFullyFromOffset(ctx.originalSigningBlock,
        ctx.signInfo.hapSigningBlockOffset) < 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "read original signing block failed");
        return false;
    }
    ctx.centralDirSize = ctx.signInfo.hapEocdOffset - ctx.signInfo.hapCentralDirOffset;
    ctx.isZip64 = ctx.signInfo.isZip64;
    if (ctx.isZip64) {
        ctx.centralDirSize -= Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH +
            Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH;
        if (!ReadZip64Eocd(inputFile, ctx.signInfo.hapEocdOffset, ctx)) {
            return false;
        }
    }
    ctx.hapEocd = ctx.signInfo.hapEocd;
    if (ctx.centralDirSize < 0) {
        PrintErrorNumberMsg("ZIP_ERROR", ZIP_ERROR, "invalid central directory size");
        return false;
    }
    return true;
}

bool TicketStaple::RebuildSigningBlock(StapleContext& ctx, const std::string& newPkcs7Der,
    int64_t& newSigningBlockSize)
{
    int64_t oldSigningBlockSize = ctx.signInfo.hapCentralDirOffset -
        ctx.signInfo.hapSigningBlockOffset;
    int32_t oldBlockSize = static_cast<int32_t>(oldSigningBlockSize);
    int32_t trailerOffset = oldBlockSize - HapUtils::HAP_SIG_BLOCK_HEADER_SIZE;
    int32_t blockCount = 0;
    ctx.originalSigningBlock.GetInt32(trailerOffset, blockCount);
    int32_t oldPkcs7Size = static_cast<int32_t>(ctx.signInfo.hapSignatureBlock.GetCapacity());
    int32_t newPkcs7Size = static_cast<int32_t>(newPkcs7Der.size());
    int32_t sizeDelta = newPkcs7Size - oldPkcs7Size;
    newSigningBlockSize = oldSigningBlockSize + sizeDelta;

    int32_t pkcs7Offset = oldBlockSize - oldPkcs7Size - HapUtils::HAP_SIG_BLOCK_HEADER_SIZE;
    int32_t newTrailerOffset = trailerOffset + sizeDelta;

    ctx.newSigningBlock.SetCapacity(static_cast<int32_t>(newSigningBlockSize));

    ctx.newSigningBlock.PutData(ctx.originalSigningBlock.GetBufferPtr(), pkcs7Offset);
    ctx.newSigningBlock.PutData(newPkcs7Der.data(), newPkcs7Size);
    ctx.newSigningBlock.PutData(ctx.originalSigningBlock.GetBufferPtr() + trailerOffset,
        HapUtils::HAP_SIG_BLOCK_HEADER_SIZE);

    static constexpr int32_t SUB_BLOCK_HEAD_SIZE = 12;
    static constexpr int32_t SUB_BLOCK_LENGTH_POS = sizeof(int32_t);
    int32_t lastHeadOffset = (blockCount - 1) * SUB_BLOCK_HEAD_SIZE;
    ctx.newSigningBlock.SetPosition(lastHeadOffset + SUB_BLOCK_LENGTH_POS);
    ctx.newSigningBlock.PutInt32(newPkcs7Size);

    ctx.newSigningBlock.SetPosition(newTrailerOffset + sizeof(int32_t));
    ctx.newSigningBlock.PutInt64(newSigningBlockSize);
    return true;
}

bool TicketStaple::UpdateZipMetadata(StapleContext& ctx, int64_t newSigningBlockSize)
{
    int64_t newCentralDirOffset = ctx.signInfo.hapSigningBlockOffset + newSigningBlockSize;
    if (!ctx.isZip64 && newCentralDirOffset > 0xFFFFFFFFLL) {
        PrintErrorNumberMsg("STAPLE_ERROR", STAPLE_ERROR,
            "staple would exceed 4GB limit, zip64 conversion requires re-signing");
        return false;
    }
    int64_t zip64Overhead = ctx.isZip64 ? 0 :
        (Zip64EndOfCentralDirectory::ZIP64_EOCD_LENGTH +
         Zip64EndOfCentralDirectoryLocator::ZIP64_EOCD_LOCATOR_LENGTH);
    int64_t newFileSize = newCentralDirOffset + ctx.centralDirSize +
        zip64Overhead + ctx.hapEocd.GetCapacity();
    if (newFileSize > HapUtils::MAX_INPUT_FILE_SIZE) {
        PrintErrorNumberMsg("STAPLE_ERROR", STAPLE_ERROR,
            "stapled file size exceeds 200GB limit");
        return false;
    }
    ctx.hapEocd.SetPosition(0);
    if (!ZipUtils::SetCentralDirectoryOffset(ctx.hapEocd, newCentralDirOffset,
        ctx.isZip64 ? &ctx.zip64Eocd : nullptr)) {
        PrintErrorNumberMsg("STAPLE_ERROR", STAPLE_ERROR, "set central directory offset failed");
        return false;
    }
    if (ctx.isZip64) {
        ctx.zip64Locator.SetZip64EocdOffset(
            static_cast<uint64_t>(newCentralDirOffset + ctx.centralDirSize));
    }
    return true;
}

bool TicketStaple::ModifyStapleData(StapleContext& ctx, const ByteBuffer& ticketData)
{
    std::string hapSigDer(ctx.signInfo.hapSignatureBlock.GetBufferPtr(),
        ctx.signInfo.hapSignatureBlock.GetCapacity());
    PKCS7Data p7Data;
    if (p7Data.Parse(hapSigDer) < 0) {
        PrintErrorNumberMsg("PARSE_ERROR", PARSE_ERROR, "parse hap signature pkcs7 failed");
        return false;
    }
    std::string ticketStr(ticketData.GetBufferPtr(), ticketData.GetCapacity());
    if (p7Data.AddUnauthenticatedAttribute(NOTARIZATION_TICKET_OID, ticketStr) < 0) {
        PrintErrorNumberMsg("STAPLE_ERROR", STAPLE_ERROR, "add ticket to unauth_attr failed");
        return false;
    }
    std::string newPkcs7Der;
    if (p7Data.Encode(newPkcs7Der) < 0) {
        PrintErrorNumberMsg("STAPLE_ERROR", STAPLE_ERROR, "re-encode pkcs7 failed");
        return false;
    }
    int64_t newSigningBlockSize = 0;
    if (!RebuildSigningBlock(ctx, newPkcs7Der, newSigningBlockSize)) {
        return false;
    }
    return UpdateZipMetadata(ctx, newSigningBlockSize);
}

bool TicketStaple::WriteStapleOutput(const std::string& backupFile,
    const std::string& tmpFile, StapleContext& ctx)
{
    RandomAccessFile inputFile;
    if (!inputFile.Init(backupFile)) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open backup file failed");
        return false;
    }
    std::ofstream output(tmpFile, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, tmpFile + " open failed");
        return false;
    }
    if (!CopyFileRange(inputFile, output, 0, ctx.signInfo.hapSigningBlockOffset,
        "read zip contents failed")) {
        output.close();
        remove(tmpFile.c_str());
        return false;
    }
    ctx.newSigningBlock.SetPosition(0);
    output.write(ctx.newSigningBlock.GetBufferPtr(), ctx.newSigningBlock.GetCapacity());
    if (!CopyFileRange(inputFile, output, ctx.signInfo.hapCentralDirOffset, ctx.centralDirSize,
        "read central directory failed")) {
        output.close();
        remove(tmpFile.c_str());
        return false;
    }
    if (ctx.isZip64) {
        std::string zip64EocdStr = ctx.zip64Eocd.ToBytes();
        output.write(zip64EocdStr.data(), zip64EocdStr.size());
        std::string locatorStr = ctx.zip64Locator.ToBytes();
        output.write(locatorStr.data(), locatorStr.size());
    }
    ctx.hapEocd.SetPosition(0);
    output.write(ctx.hapEocd.GetBufferPtr(), ctx.hapEocd.GetCapacity());
    output.flush();
    output.close();
    return true;
}

bool TicketStaple::StapleApp(Options* options)
{
    std::string inFile = options->GetString(Options::IN_FILE);
    std::string backupFile = inFile + ".staplebak";
    std::string tmpFile = inFile + ".stapletmp";
    std::string ticketFile = options->GetString(Options::TICKET_FILE);
    ByteBuffer ticketData;
    if (!HapUtils::ReadFileToByteBuffer(ticketFile, ticketData) || ticketData.GetCapacity() == 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, ticketFile + " is empty or read failed");
        return false;
    }
    StapleContext ctx;
    if (!ExtractStapleInfo(inFile, ctx)) {
        return false;
    }
    if (!ModifyStapleData(ctx, ticketData)) {
        return false;
    }
    if (rename(inFile.c_str(), backupFile.c_str()) != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "backup original file failed: " + inFile);
        return false;
    }
    if (!WriteStapleOutput(backupFile, tmpFile, ctx)) {
        if (remove(tmpFile.c_str()) != 0) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "remove " + tmpFile + " failed");
        }
        if (rename(backupFile.c_str(), inFile.c_str()) != 0) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "restore " + backupFile + " failed");
        }
        return false;
    }
    if (rename(tmpFile.c_str(), inFile.c_str()) != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR,
            "rename " + tmpFile + " to " + inFile + " failed");
        if (remove(tmpFile.c_str()) != 0) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "remove " + tmpFile + " failed");
        }
        if (rename(backupFile.c_str(), inFile.c_str()) != 0) {
            PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "restore " + backupFile + " failed");
        }
        return false;
    }
    if (remove(backupFile.c_str()) != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "remove " + backupFile + " failed");
    }
    return true;
}

} // namespace SignatureTools
} // namespace OHOS
