using SnowplowCLI.Utils;
using SnowplowCLI.Utils.Compression;
using SnowplowCLI.Utils.Crypto;
using System.IO.Compression;

namespace SnowplowCLI
{
    public class SDFS
    {
        public uint decompressedFileTableSize;
        public uint dataOffset;
        public uint compressedFileTableSize;
        public uint firstInstallPart;
        public uint installPartCount;
        public uint[] installPartSizes;
        public uint ddsHeaderCount;
        public DDSHeader[] ddsHeaders;
        public byte tocFlag0;
        public byte tocFlag1;
        public bool tocEncrypted;
        public uint tocHeaderSize;
        public uint tocTableCountA;
        public uint tocTableCountB;
        public uint fileTableCompressedSize;
        public long fileTableOffset;
        public FileTable fileTable;
        public Action<string>? LogInfo;
        public Action<string>? LogProgress;

        public void Initalise(DataStream stream, uint version, string seperator, long? fileTableOffsetOverride = null, byte[]? tocKey = null, byte[]? tocIv = null)
        {
            //
            //initalises the file system
            //
            decompressedFileTableSize = stream.ReadUInt32();
            if (version >= 0x17)
                dataOffset = stream.ReadUInt32();
            compressedFileTableSize = stream.ReadUInt32();
            firstInstallPart = stream.ReadUInt32();
            installPartCount = stream.ReadUInt32(); //count of sdfdata archives
            ddsHeaderCount = stream.ReadUInt32();
            ID startId = new ID(stream);
            LogInfo?.Invoke($"TOC header: decompressedTableSize={decompressedFileTableSize} compressedTableSize={compressedFileTableSize} dataOffset=0x{dataOffset:X} installPartCount={installPartCount} ddsHeaderCount={ddsHeaderCount}");

            tocFlag0 = stream.ReadByte();
            tocFlag1 = 0;
            if (version >= 0x2A)
            {
                tocFlag1 = stream.ReadByte();
            }
            tocEncrypted = tocFlag1 != 0;
            LogInfo?.Invoke($"TOC flags: extraHeader={(tocFlag0 != 0 ? "yes" : "no")} encrypted={(tocEncrypted ? "yes" : "no")}");

            if (tocFlag0 != 0)
            {
                byte[] unk1 = stream.ReadBytes(0x140); //no idea whats contained in these bytes
            }

            long metadataStart = stream.Position;
            tocHeaderSize = (uint)(tocFlag0 != 0 ? 526 : 206);
            if (version < 0x20)
            {
                try
                {
                    if (installPartCount > 0 && stream.Position + (long)installPartCount * 4 <= stream.Length)
                    {
                        installPartSizes = new uint[installPartCount];
                        for (int i = 0; i < installPartCount; i++)
                        {
                            installPartSizes[i] = stream.ReadUInt32();
                        }

                        ID[] installPartIds = new ID[installPartCount]; //read installPart ids
                        for (int i = 0; i < installPartCount; i++)
                        {
                            installPartIds[i] = new ID(stream);
                        }
                    }
                    else
                    {
                        installPartSizes = Array.Empty<uint>();
                    }

                    if (ddsHeaderCount > 0 && stream.Position + (long)ddsHeaderCount * 204 <= stream.Length)
                    {
                        ddsHeaders = new DDSHeader[ddsHeaderCount]; //read dds headers
                        for (int i = 0; i < ddsHeaderCount; i++)
                        {
                            ddsHeaders[i] = new DDSHeader(stream);
                        }
                    }
                    else
                    {
                        ddsHeaders = Array.Empty<DDSHeader>();
                    }
                }
                catch
                {
                    stream.Position = metadataStart;
                    installPartSizes = Array.Empty<uint>();
                    ddsHeaders = Array.Empty<DDSHeader>();
                }
            }
            else
            {
                installPartSizes = Array.Empty<uint>();
                ddsHeaders = Array.Empty<DDSHeader>();
                stream.Position = metadataStart;
            }

            fileTableCompressedSize = compressedFileTableSize;
            bool tableSizeFromDataOffset = false;
            if (fileTableCompressedSize == 0 && version >= 0x2A && dataOffset != 0)
            {
                fileTableCompressedSize = dataOffset;
                tableSizeFromDataOffset = true;
            }
            if (tableSizeFromDataOffset)
            {
                LogInfo?.Invoke($"Using dataOffset as compressed file table size: 0x{fileTableCompressedSize:X}");
                long remainder = stream.Length - fileTableCompressedSize - tocHeaderSize - (long)ddsHeaderCount * 0x98 - (long)installPartCount * 8;
                if (remainder >= 0 && remainder % 60 == 0)
                {
                    long unknownCount = remainder / 60;
                    LogInfo?.Invoke($"Computed 60-byte entry count: {unknownCount} (headerSize={tocHeaderSize})");
                }
            }

            if (tocEncrypted && (tocKey == null || tocIv == null))
                throw new Exception("TOC file table is encrypted but no key/iv provided. Use --key and --iv.");

            byte[] decompressedFileTable;
            if (compressedFileTableSize > 0)
            {
                long tableOffset = stream.Position;
                if (dataOffset != 0)
                {
                    tableOffset = dataOffset + 0x51; //legacy toc block offset
                }

                stream.Position = tableOffset;
                byte[] compressedFileTable = stream.ReadBytes((int)compressedFileTableSize);
                if (tocEncrypted)
                {
                    SdfTocCrypto.DecryptInPlace(compressedFileTable, tocKey!, tocIv!);
                }
                uint signature = BitConverter.ToUInt32(compressedFileTable, 0);
                LogInfo?.Invoke($"File table signature: 0x{signature:X8}");
                decompressedFileTable = DecompressFileTable(signature, compressedFileTable, decompressedFileTableSize, version);
                fileTableOffset = tableOffset;
            }
            else
            {
                if (version >= 0x2A && !fileTableOffsetOverride.HasValue)
                {
                    ParseTocContentV2A(stream, tocKey, tocIv, version, seperator);
                    return;
                }

                bool allowScan = version < 0x2A;
                if (tableSizeFromDataOffset)
                {
                    const int footerSize = 0x30;
                    long candidateOffset = stream.Length - footerSize - fileTableCompressedSize;
                    if (candidateOffset <= metadataStart || candidateOffset < 0)
                    {
                        LogInfo?.Invoke($"Computed file table offset (0x{candidateOffset:X}) is invalid, falling back to scan.");
                    }
                    else
                    {
                        LogInfo?.Invoke($"Computed file table offset: 0x{candidateOffset:X} (compressedSize=0x{fileTableCompressedSize:X}, footer=0x{footerSize:X})");
                        stream.Position = candidateOffset;
                        byte[] compressedFileTable = stream.ReadBytes((int)fileTableCompressedSize);
                        if (tocEncrypted)
                        {
                            SdfTocCrypto.DecryptInPlace(compressedFileTable, tocKey!, tocIv!);
                        }

                        if (!TryDecompressZlibFromBuffer(compressedFileTable, 0, decompressedFileTableSize, out decompressedFileTable))
                        {
                            LogInfo?.Invoke("Failed to decompress file table at computed offset, falling back to scan.");
                        }
                        else
                        {
                            fileTableOffset = candidateOffset;
                            goto FILE_TABLE_READY;
                        }
                    }
                }

                if (fileTableOffsetOverride.HasValue)
                {
                    long offset = fileTableOffsetOverride.Value;
                    if (offset < 0 || offset >= stream.Length)
                        throw new Exception($"Invalid file table offset override: 0x{offset:X}");

                    LogInfo?.Invoke($"Trying zlib file table at override offset 0x{offset:X}...");
                    stream.Position = offset;
                    byte[] buffer = stream.ReadBytes((int)(stream.Length - offset));
                    if (tocEncrypted)
                    {
                        SdfTocCrypto.DecryptInPlace(buffer, tocKey!, tocIv!);
                    }
                    if (!TryDecompressZlibFromBuffer(buffer, 0, decompressedFileTableSize, out decompressedFileTable))
                        throw new Exception("Failed to decompress file table at override offset.");
                    fileTableOffset = offset;
                }
                else
                {
                    if (!allowScan)
                        throw new Exception("File table offset not resolved. Provide --offset for this TOC version.");

                    long scanStart = metadataStart;
                    long scanEnd = stream.Length;
                    if (dataOffset != 0 && dataOffset > scanStart && dataOffset <= stream.Length)
                    {
                        scanEnd = dataOffset;
                    }

                    LogInfo?.Invoke($"Searching zlib file table in range 0x{scanStart:X}-0x{scanEnd:X}...");
                    if (tocEncrypted)
                        throw new Exception("Encrypted TOC requires --key and --iv and a resolvable file table offset.");

                    if (!TryFindZlibFileTable(stream, scanStart, scanEnd, decompressedFileTableSize, out decompressedFileTable))
                    {
                        throw new Exception("Failed to locate zlib-compressed file table.");
                    }
                }
            }

        FILE_TABLE_READY:
            if (version >= 0x2A && ddsHeaderCount > 0 && fileTableOffset > 0)
            {
                TryReadDdsHeadersFromBeforeFileTable(stream, fileTableOffset, version);
            }

            fileTable = ReadFileTable(decompressedFileTable, version, seperator);

        }

        private void ParseTocContentV2A(DataStream stream, byte[]? tocKey, byte[]? tocIv, uint version, string seperator)
        {
            long originalPosition = stream.Position;
            try
            {
                long prefixSize = tocHeaderSize - 0x30;
                if (prefixSize < 0 || prefixSize >= stream.Length)
                    throw new Exception("Invalid header size for v0x2A.");

                tocTableCountA = installPartCount;
                long remainder = stream.Length - fileTableCompressedSize - tocHeaderSize - (long)ddsHeaderCount * 0x98 - (long)tocTableCountA * 8;
                if (remainder < 0 || remainder % 60 != 0)
                    throw new Exception("Failed to resolve dataslice table size for v0x2A.");

                tocTableCountB = (uint)(remainder / 60);
                LogInfo?.Invoke($"Computed tables: countA={tocTableCountA} countB={tocTableCountB} headerSize={tocHeaderSize}");

                stream.Position = prefixSize + (long)tocTableCountA * 8 + (long)tocTableCountB * 60;

                if (ddsHeaderCount > 0)
                {
                    ddsHeaders = new DDSHeader[ddsHeaderCount];
                    for (int i = 0; i < ddsHeaderCount; i++)
                    {
                        ddsHeaders[i] = new DDSHeader(stream, 0x94);
                    }
                    LogDdsHeaderSummary();
                }
                else
                {
                    ddsHeaders = Array.Empty<DDSHeader>();
                }

                fileTableOffset = stream.Position;
                byte[] compressedFileTable = stream.ReadBytes((int)fileTableCompressedSize);
                if (tocEncrypted)
                {
                    SdfTocCrypto.DecryptInPlace(compressedFileTable, tocKey!, tocIv!);
                }

                if (!TryDecompressZlibFromBuffer(compressedFileTable, 0, decompressedFileTableSize, out byte[] decompressed))
                {
                    throw new Exception("Failed to decompress file table for v0x2A.");
                }

                if (stream.Position + 0x30 <= stream.Length)
                {
                    byte[] footer = stream.ReadBytes(0x30);
                    string footerText = System.Text.Encoding.ASCII.GetString(footer);
                    if (footerText.Contains("massive", StringComparison.OrdinalIgnoreCase) &&
                        footerText.Contains("ubisoft", StringComparison.OrdinalIgnoreCase))
                    {
                        LogInfo?.Invoke("Footer ID block verified.");
                    }
                    else
                    {
                        LogInfo?.Invoke("Footer ID block mismatch.");
                    }
                }

                fileTable = ReadFileTable(decompressed, version, seperator);
                return;
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }


        public byte[] RequestFileData(SDFS fs, FileEntry fileEntry, string path, FileStreamCache streamCache, string? language = null, Action<string>? logInfo = null, Action<string>? logError = null)
        {
            List<byte[]> fileData = new List<byte[]>();

            string installPartPath = Path.Combine(path, fileEntry.installPartName);
            if (!File.Exists(installPartPath))
            {
                string? altPath = FindInstallPartWithSuffix(path, fileEntry.installPartName, language);
                if (!string.IsNullOrEmpty(altPath))
                {
                    installPartPath = altPath;
                }
                else
                {
                    throw new FileNotFoundException($"Missing install part: {installPartPath}");
                }
            }

            using (var lease = streamCache.Acquire(installPartPath))
            {
                FileStream fileStream = lease.Stream;
                byte[]? pendingDdsHeader = null;
                if (TryGetDdsHeaderBytes(fileEntry, out byte[] headerBytes))
                {
                    pendingDdsHeader = headerBytes;
                }

                if (fileEntry.compressedSizes.Count == 0)
                {
                    byte[] data = ReadAt(fileStream, (long)fileEntry.filePartoffset, (int)fileEntry.decompressedSize);
                    if (pendingDdsHeader != null)
                    {
                        fileData.Add(pendingDdsHeader);
                    }
                    fileData.Add(data);
                }
                else
                {
                    var pageSize = (double)0x10000;
                    var decompOffset = 0;
                    var compOffset = 0;

                    for (var i = 0; i < fileEntry.compressedSizes.Count; i++)
                    {
                        var decompressedSize = (int)Math.Min((int)fileEntry.decompressedSize - decompOffset, pageSize);
                        int compressedSize = (int)fileEntry.compressedSizes[i];
                        byte[] chunkData;
                        if (compressedSize == 0 || decompressedSize == compressedSize)
                        {
                            chunkData = ReadAt(fileStream, (long)fileEntry.filePartoffset + compOffset, decompressedSize);
                            compressedSize = decompressedSize;
                        }
                        else
                        {
                            byte[] compressedChunk = ReadAt(fileStream, (long)fileEntry.filePartoffset + compOffset, compressedSize);
                            chunkData = DecompressChunk(compressedChunk);
                        }

                        if (pendingDdsHeader != null)
                        {
                            fileData.Add(pendingDdsHeader);
                            pendingDdsHeader = null;
                        }

                        fileData.Add(chunkData);
                        decompOffset += decompressedSize;
                        compOffset += compressedSize;
                    }
                }
            }

            return CombineByteArray(fileData.ToArray());
        }

        public bool TryGetDdsHeaderBytes(FileEntry entry, out byte[] header)
        {
            return TryGetDdsHeaderBytes(entry, out header, out _, out _);
        }

        public bool TryGetDdsHeaderBytes(FileEntry entry, out byte[] header, out int resolvedIndex, out string matchKind)
        {
            header = Array.Empty<byte>();
            resolvedIndex = -1;
            matchKind = "none";
            if (!entry.isDDS || ddsHeaders == null || ddsHeaders.Length == 0)
                return false;

            ulong headerIndex = entry.ddsHeaderIndex;
            if (headerIndex >= (ulong)ddsHeaders.Length)
            {
                uint id = (uint)headerIndex;
                for (int i = 0; i < ddsHeaders.Length; i++)
                {
                    if (ddsHeaders[i].unk == id)
                    {
                        resolvedIndex = i;
                        matchKind = "id";
                        break;
                    }
                }
                if (resolvedIndex < 0)
                    return false;
            }
            else
            {
                resolvedIndex = (int)headerIndex;
                matchKind = "index";
            }

            if (!TryBuildDdsHeaderBytes(ddsHeaders[resolvedIndex], out byte[] full))
                return false;

            if (!StartsWithDdsMagic(full) && entry.ddsType != 0)
            {
                uint type = (uint)entry.ddsType;
                for (int i = 0; i < ddsHeaders.Length; i++)
                {
                    if (ddsHeaders[i].unk == type)
                    {
                        if (TryBuildDdsHeaderBytes(ddsHeaders[i], out byte[] typeFull))
                        {
                            full = typeFull;
                            resolvedIndex = i;
                            matchKind = "type";
                        }
                        break;
                    }
                }
            }

            bool isDx10 = full.Length >= 88 &&
                          full[84] == (byte)'D' &&
                          full[85] == (byte)'X' &&
                          full[86] == (byte)'1' &&
                          full[87] == (byte)'0';

            int desiredLength = isDx10 ? 0x94 : 0x80;
            if (full.Length < desiredLength)
                desiredLength = full.Length;

            header = new byte[desiredLength];
            Buffer.BlockCopy(full, 0, header, 0, desiredLength);
            return true;
        }

        private static bool StartsWithDdsMagic(byte[] data)
        {
            return data.Length >= 4 &&
                   data[0] == (byte)'D' &&
                   data[1] == (byte)'D' &&
                   data[2] == (byte)'S' &&
                   data[3] == (byte)' ';
        }

        private static bool TryBuildDdsHeaderBytes(DDSHeader ddsHeader, out byte[] full)
        {
            full = Array.Empty<byte>();
            byte[] data = ddsHeader.data ?? Array.Empty<byte>();
            if (data.Length < 4 && ddsHeader.unk != 0x20534444)
                return false;

            if (StartsWithDdsMagic(data))
            {
                full = data;
                return true;
            }

            if (ddsHeader.unk == 0x20534444)
            {
                full = new byte[data.Length + 4];
                byte[] magicBytes = BitConverter.GetBytes(ddsHeader.unk);
                Buffer.BlockCopy(magicBytes, 0, full, 0, 4);
                Buffer.BlockCopy(data, 0, full, 4, data.Length);
                return true;
            }

            full = data;
            return true;
        }

        #region File Table

        public FileTable ReadFileTable(uint signature, byte[] compressedFileTable, uint decompressedFileTableSize, uint version, string seperator)
        {
            //
            //calls to decompress the file table and then passes it to the parser
            //
            byte[] decompressedFileTable = DecompressFileTable(signature, compressedFileTable, decompressedFileTableSize, version); //decompress the file table
            return ReadFileTable(decompressedFileTable, version, seperator);
        }

        public FileTable ReadFileTable(byte[] decompressedFileTable, uint version, string seperator)
        {
            MemoryStream stream = new MemoryStream(decompressedFileTable); //convert to stream

            using (DataStream stream1 = new DataStream(stream))
            {
                FileTable fileTable = new FileTable();
                ParseFileTable(stream1, fileTable, version, seperator); //parse!
                return fileTable;
            }
        }

        private bool TryFindZlibFileTable(DataStream stream, long scanStart, long scanEnd, uint expectedSize, out byte[] decompressedFileTable)
        {
            decompressedFileTable = Array.Empty<byte>();

            if (scanEnd <= scanStart)
                return false;

            long originalPosition = stream.Position;
            try
            {
                if (scanEnd > stream.Length)
                    scanEnd = stream.Length;

                int scanLength = (int)(scanEnd - scanStart);
                stream.Position = scanStart;
                byte[] buffer = stream.ReadBytes(scanLength);

                int headerCount = 0;
                int lastReport = 0;
                int reportInterval = 1 << 20; // 1 MB
                for (int i = 0; i < buffer.Length - 1; i++)
                {
                    if (i - lastReport >= reportInterval)
                    {
                        double percent = (i * 100.0) / buffer.Length;
                        string message = $"Progress: scanning file table {percent:0.0}% ({i}/{buffer.Length}), headers tried: {headerCount}";
                        LogProgress?.Invoke(message);
                        LogInfo?.Invoke(message);
                        lastReport = i;
                    }

                    if (!Zlib.IsZlibHeader(buffer.AsSpan(i)))
                        continue;

                    headerCount++;
                    if (headerCount % 100 == 0)
                    {
                        LogInfo?.Invoke($"Tried {headerCount} zlib headers (last at 0x{(scanStart + i):X})");
                    }

                    if (TryDecompressZlibFromBuffer(buffer, i, expectedSize, out decompressedFileTable))
                    {
                        LogInfo?.Invoke($"Found zlib file table at 0x{(scanStart + i):X}");
                        return true;
                    }
                }

                LogInfo?.Invoke($"Scan complete. Tried {headerCount} zlib headers.");
                return false;
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private void TryReadDdsHeadersFromBeforeFileTable(DataStream stream, long tableOffset, uint version)
        {
            if (ddsHeaderCount == 0)
            {
                ddsHeaders = Array.Empty<DDSHeader>();
                return;
            }

            int entrySize = version >= 0x2A ? 0x98 : 0xCC;
            long headersSize = (long)ddsHeaderCount * entrySize;
            long start = tableOffset - headersSize;
            if (start < 0 || start >= stream.Length)
            {
                LogInfo?.Invoke($"DDS header block out of range (start=0x{start:X}, size=0x{headersSize:X}).");
                ddsHeaders = Array.Empty<DDSHeader>();
                return;
            }

            long originalPosition = stream.Position;
            try
            {
                stream.Position = start;
                ddsHeaders = new DDSHeader[ddsHeaderCount];
                int dataSize = entrySize - 4;
                for (int i = 0; i < ddsHeaderCount; i++)
                {
                    ddsHeaders[i] = new DDSHeader(stream, dataSize);
                }
                LogInfo?.Invoke($"Read DDS headers: count={ddsHeaderCount} entrySize=0x{entrySize:X} offset=0x{start:X}");
                LogDdsHeaderSummary();
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private void LogDdsHeaderSummary()
        {
            if (LogInfo == null || ddsHeaders == null || ddsHeaders.Length == 0)
                return;

            for (int i = 0; i < ddsHeaders.Length; i++)
            {
                DDSHeader header = ddsHeaders[i];
                byte[] data = header.data ?? Array.Empty<byte>();
                bool dataMagic = StartsWithDdsMagic(data);
                string dataPrefix = data.Length >= 4
                    ? $"{data[0]:X2}{data[1]:X2}{data[2]:X2}{data[3]:X2}"
                    : "n/a";
                LogInfo($"DDS header[{i}] unk=0x{header.unk:X8} dataLen=0x{data.Length:X} dataMagic={(dataMagic ? "yes" : "no")} dataPrefix={dataPrefix}");
            }
        }

        private static bool TryDecompressZlibFromBuffer(byte[] buffer, int offset, uint expectedSize, out byte[] output)
        {
            output = Array.Empty<byte>();
            try
            {
                using (var input = new MemoryStream(buffer, offset, buffer.Length - offset, false))
                using (var zlib = new ZLibStream(input, CompressionMode.Decompress))
                using (var outputStream = new MemoryStream((int)expectedSize))
                {
                    byte[] temp = new byte[8192];
                    while (true)
                    {
                        int read = zlib.Read(temp, 0, temp.Length);
                        if (read == 0)
                            break;

                        outputStream.Write(temp, 0, read);

                        if (outputStream.Length > expectedSize)
                            return false;
                    }

                    if (outputStream.Length != expectedSize)
                        return false;

                    output = outputStream.ToArray();
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public void ParseFileTable(DataStream stream, FileTable fileTable, uint version, string seperator, string name = "")
        {
            //
            //adapted from https://github.com/KillzXGaming/Switch-Toolbox/blob/master/File_Format_Library/FileFormats/Archives/SDF.cs#L366
            //
            char ch = stream.ReadChar();

            if (ch == 0)
                throw new Exception("Unexcepted byte in file tree");

            if (ch >= 1 && ch <= 0x1f) //string part
            {
                while (ch-- > 0)
                {
                    name += stream.ReadChar();
                }

                ParseFileTable(stream, fileTable, version, seperator, name);
            }
            else if (ch >= 'A' && ch <= 'Z') //file entry
            {
                int var = Convert.ToInt32(ch - 'A');

                ch = Convert.ToChar(var);
                int count1 = ch & 7;
                int flag1 = (ch >> 3) & 1;
                //   int flag1 = ch & 8;

                if (count1 > 0)
                {
                    uint strangeId = stream.ReadUInt32();
                    byte chr2 = stream.ReadByte();
                    int byteCount = chr2 & 3;
                    int byteValue = chr2 >> 2;
                    ulong ddsType = ReadVariadicInteger(byteCount, stream);

                    for (int chunkIndex = 0; chunkIndex < count1; chunkIndex++)
                    {
                        byte ch3 = stream.ReadByte();
                        // if (ch3 == 0)
                        //    {
                        //        break;
                        //    }

                        int compressedSizeByteCount = (ch3 & 3) + 1;
                        int filePartOffsetByteCount = (ch3 >> 2) & 7;
                        bool hasCompression = ((ch3 >> 5) & 1) != 0;

                        ulong decompressedSize = 0;
                        ulong compressedSize = 0;
                        ulong filePartOffset = 0;
                        long fileId = -1;

                        if (compressedSizeByteCount > 0)
                        {
                            decompressedSize = ReadVariadicInteger(compressedSizeByteCount, stream);
                        }
                        if (hasCompression)
                        {
                            compressedSize = ReadVariadicInteger(compressedSizeByteCount, stream);
                        }
                        if (filePartOffsetByteCount != 0)
                        {
                            filePartOffset = ReadVariadicInteger(filePartOffsetByteCount, stream);
                        }

                        ulong installPartId = ReadVariadicInteger(2, stream);


                        List<ulong> compSizeArray = new List<ulong>();

                        if (hasCompression)
                        {
                            ulong pageCount = (decompressedSize + 0xffff) >> 16;
                            //   var pageCount = NextMultiple(decompressedSize, 0x10000) / 0x10000;
                            if (pageCount > 1)
                            {
                                for (ulong page = 0; page < pageCount; page++)
                                {
                                    ulong compSize = ReadVariadicInteger(2, stream);
                                    compSizeArray.Add(compSize);
                                }
                            }
                        }

                        if (version < 0x16) //Unsure. Rabbids doesn't use it, newer versions don't. 
                        {
                            fileId = (long)ReadVariadicInteger(4, stream);
                        }

                        if (compSizeArray.Count == 0 && hasCompression)
                            compSizeArray.Add(compressedSize);

                        AddFileEntry(
                            fileTable.fileEntries,
                            name,
                            installPartId,
                            seperator,
                            filePartOffset,
                            hasCompression,
                            compSizeArray,
                            decompressedSize,
                            byteCount != 0 && chunkIndex == 0,
                            (ulong)byteValue,
                            ddsType,
                            chunkIndex != 0);
                    }
                }
                if ((ch & 8) != 0) //flag1
                {
                    byte ch3 = stream.ReadByte();
                    while (ch3-- > 0)
                    {
                        stream.ReadByte();
                        stream.ReadByte();
                    }
                }
            }
            else
            {
                uint offset = stream.ReadUInt32();
                ParseFileTable(stream, fileTable, version, seperator, name);
                stream.Seek(offset, SeekOrigin.Begin);
                ParseFileTable(stream, fileTable, version, seperator, name);
            }

        }

        public byte[] DecompressFileTable(uint signature, byte[] compressedFileTable, uint decompressedFileTableSize, uint version)
        {
            //
            //checks compression type and decompresses the file table
            //
            byte[] decompressedFileTable = new byte[decompressedFileTableSize];
            if (signature == 0xDFF25B82 || signature == 0xFD2FB528) //zstd
            {
                decompressedFileTable = Zstd.Decompress(compressedFileTable);
                return decompressedFileTable;
            }
            else if (signature == 0x184D2204 || version >= 0x17) //lz4
            {
                decompressedFileTable = Lz4.Decompress(compressedFileTable);
                return decompressedFileTable;
            }
            else //zlib
            {
                decompressedFileTable = Zlib.Decompress(compressedFileTable);
                return decompressedFileTable;
            }

        }

        #endregion

        #region Utility Functions

        private static string? FindInstallPartWithSuffix(string installDir, string installPartName, string? language)
        {
            if (!Directory.Exists(installDir))
                return null;

            string baseName = Path.GetFileNameWithoutExtension(installPartName);
            string pattern = $"{baseName}*.sdfdata";
            IEnumerable<string> matches = Directory.EnumerateFiles(installDir, pattern);
            if (!string.IsNullOrEmpty(language))
            {
                string lang = language.ToLowerInvariant();
                foreach (string path in matches)
                {
                    string name = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
                    if (name.Contains("-" + lang) || name.Contains("_" + lang))
                    {
                        return path;
                    }
                }
                return null;
            }

            return matches.FirstOrDefault();
        }

        private static byte[] ReadAt(FileStream stream, long offset, int count)
        {
            byte[] buffer = new byte[count];
            int readTotal = 0;
            while (readTotal < count)
            {
                int read = RandomAccess.Read(stream.SafeFileHandle, buffer.AsSpan(readTotal), offset + readTotal);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                readTotal += read;
            }
            return buffer;
        }

        private static byte[] DecompressChunk(byte[] compressedChunk)
        {
            if (Zstd.IsZstdFrame(compressedChunk))
            {
                return Zstd.Decompress(compressedChunk);
            }

            if (Lz4.IsLz4Frame(compressedChunk))
            {
                return Lz4.Decompress(compressedChunk);
            }

            if (Zlib.IsZlibHeader(compressedChunk))
            {
                return Zlib.Decompress(compressedChunk);
            }

            return Zstd.Decompress(compressedChunk);
        }


        public void AddFileEntry(List<FileEntry> fileEntries, string fileName, ulong installPartId, string seperator, ulong filePartoffset, bool isCompressed, List<ulong> compressedSizes, ulong decompressedSize, bool isDDS, ulong ddsHeaderIndex, ulong ddsType, bool isChunk)
        {
            //
            //adds a file entry to the file table
            //
            string installPartName = GetinstallPartName(installPartId, seperator);
            fileEntries.Add(new FileEntry()
            {
                fileName = fileName,
                installPartName = installPartName,
                installPartId = installPartId,
                filePartoffset = filePartoffset,
                isCompressed = isCompressed,
                compressedSizes = compressedSizes,
                decompressedSize = decompressedSize,
                isDDS = isDDS,
                ddsHeaderIndex = ddsHeaderIndex,
                ddsType = ddsType,
                isChunk = isChunk
            });
        }

        public string GetinstallPartName(ulong installPartId, string seperator)
        {
            //
            //get sdfdata installPart name for a specified installPartId
            //
            string installPartLayer;
            if (installPartId < 1000) installPartLayer = "A";
            else if (installPartId < 2000) installPartLayer = "B";
            else if (installPartId < 3000) installPartLayer = "C";
            else installPartLayer = "D";

            string installPartName = $"sdf{seperator}{installPartLayer}{seperator}{installPartId.ToString("D" + 4)}.sdfdata";
            return installPartName;
        }

        private ulong ReadVariadicInteger(int Count, DataStream stream)
        {
            //
            //adapted from https://github.com/KillzXGaming/Switch-Toolbox/blob/master/File_Format_Library/FileFormats/Archives/SDF.cs#L228
            //
            ulong result = 0;

            for (int i = 0; i < Count; i++)
            {
                result |= (ulong)(stream.ReadByte()) << (i * 8);
            }
            return result;
        }
        public static byte[] CombineByteArray(params byte[][] arrays)
        {
            //
            //from https://github.com/KillzXGaming/Switch-Toolbox/blob/master/Switch_Toolbox_Library/Util/Util.cs#L155
            //
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        #endregion

        #region Classes

        public class FileTable
        {
            public List<FileEntry> fileEntries = new List<FileEntry>();
        }

        public class FileEntry
        {
            public string fileName;
            public string installPartName;
            public ulong installPartId;
            public ulong filePartoffset;
            public bool isCompressed;
            public List<ulong> compressedSizes;
            public ulong decompressedSize;
            public bool isDDS;
            public ulong ddsHeaderIndex;
            public ulong ddsType;
            public bool isChunk;
        }

        public class ID
        {
            public string massive;
            public byte[] data;
            public string ubisoft;

            public ID(DataStream stream)
            {
                massive = stream.ReadNullTerminatedString();
                data = stream.ReadBytes(0x20); //unsure what method this uses
                ubisoft = stream.ReadNullTerminatedString();
            }
        }

        public class DDSHeader
        {
            public uint unk;
            public byte[] data;

            public DDSHeader(DataStream stream, int dataSize = 200)
            {
                unk = stream.ReadUInt32();
                data = stream.ReadBytes(dataSize); //approximation of the dds header size. hopefully this works

            }
        } 
        #endregion

    }

}
