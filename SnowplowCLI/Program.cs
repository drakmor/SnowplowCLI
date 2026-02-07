using SnowplowCLI.Utils;
using SnowplowCLI.Utils.Compression;
using System.Globalization;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Text;
using static SnowplowCLI.SDFS;

namespace SnowplowCLI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 2 || args.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase)))
            {
                PrintUsage();
                return;
            }

            string tocPath = args[0];
            string dumpPath = args[1];
            string installDir = Path.GetDirectoryName(tocPath);

            if (!File.Exists(tocPath))
            {
                Console.WriteLine("File does not exist.");
                return;
            }

            Directory.CreateDirectory(dumpPath);
            string logPath = Path.Combine(dumpPath, "snowplow.log");
            object logLock = new object();
            using var logWriter = new StreamWriter(logPath, false, System.Text.Encoding.UTF8);
            logWriter.AutoFlush = true;

            void LogInfo(string message)
            {
                lock (logLock)
                {
                    logWriter.WriteLine($"[{DateTime.Now:O}] INFO  {message}");
                }
            }

            void LogError(string message)
            {
                lock (logLock)
                {
                    logWriter.WriteLine($"[{DateTime.Now:O}] ERROR {message}");
                }
                Console.WriteLine(message);
            }

            LogInfo($"TOC: {tocPath}");
            LogInfo($"Output: {dumpPath}");
            LogInfo("Reading TOC...");

            byte[] tocBytes = File.ReadAllBytes(tocPath);
            if (GetMagic(tocBytes) != "WEST")
            {
                LogInfo("TOC is compressed, attempting to decompress...");
                if (!TryDecompressToc(tocBytes, out byte[] decompressed))
                {
                    LogError("Not a valid TOC.");
                    return;
                }

                tocBytes = decompressed;
                LogInfo($"TOC decompressed ({tocBytes.Length} bytes).");
            }

            long? fileTableOffsetOverride = null;
            string? language = null;
            bool listParts = false;
            bool allParts = false;
            bool listDdsFlags = false;
            byte[]? tocKey = null;
            byte[]? tocIv = null;
            if (args.Length >= 3)
            {
                for (int i = 2; i < args.Length; i++)
                {
                    string arg = args[i];
                    if (arg.Equals("--list-parts", StringComparison.OrdinalIgnoreCase))
                    {
                        listParts = true;
                        continue;
                    }
                    if (arg.Equals("--all-parts", StringComparison.OrdinalIgnoreCase))
                    {
                        allParts = true;
                        continue;
                    }
                    if (arg.Equals("--list-dds-flags", StringComparison.OrdinalIgnoreCase))
                    {
                        listDdsFlags = true;
                        continue;
                    }
                    if (arg.StartsWith("--lang=", StringComparison.OrdinalIgnoreCase))
                    {
                        language = arg.Substring("--lang=".Length);
                        continue;
                    }
                    if (arg.StartsWith("--key=", StringComparison.OrdinalIgnoreCase))
                    {
                        tocKey = ParseKeyMaterial(arg.Substring("--key=".Length));
                        continue;
                    }
                    if (arg.Equals("--key", StringComparison.OrdinalIgnoreCase))
                    {
                        if (i + 1 < args.Length)
                        {
                            tocKey = ParseKeyMaterial(args[++i]);
                        }
                        continue;
                    }
                    if (arg.StartsWith("--iv=", StringComparison.OrdinalIgnoreCase))
                    {
                        tocIv = ParseKeyMaterial(arg.Substring("--iv=".Length));
                        continue;
                    }
                    if (arg.Equals("--iv", StringComparison.OrdinalIgnoreCase))
                    {
                        if (i + 1 < args.Length)
                        {
                            tocIv = ParseKeyMaterial(args[++i]);
                        }
                        continue;
                    }
                    if (arg.Equals("--lang", StringComparison.OrdinalIgnoreCase) || arg.Equals("-l", StringComparison.OrdinalIgnoreCase))
                    {
                        if (i + 1 < args.Length)
                        {
                            language = args[++i];
                        }
                        continue;
                    }
                    if (arg.StartsWith("--offset=", StringComparison.OrdinalIgnoreCase))
                    {
                        string value = arg.Substring("--offset=".Length);
                        if (TryParseOffset(value, out long parsed))
                        {
                            fileTableOffsetOverride = parsed;
                        }
                        continue;
                    }
                    if (fileTableOffsetOverride == null && TryParseOffset(arg, out long parsedOffset))
                    {
                        fileTableOffsetOverride = parsedOffset;
                    }
                }
            }

            if (fileTableOffsetOverride.HasValue)
            {
                Console.WriteLine($"Using file table offset override: 0x{fileTableOffsetOverride.Value:X}");
            }
            if (tocKey != null)
            {
                LogInfo($"TOC key provided (length={tocKey.Length}).");
            }
            if (tocIv != null)
            {
                LogInfo($"TOC IV provided (length={tocIv.Length}).");
            }
            if (!string.IsNullOrWhiteSpace(language))
            {
                language = language.Trim();
                LogInfo($"Language filter: {language}");
            }
            if (allParts && !string.IsNullOrWhiteSpace(language))
            {
                LogInfo("Language filter ignored because --all-parts was specified.");
            }

            using (DataStream stream = new DataStream(new MemoryStream(tocBytes)))
            {
                string idCheck = stream.ReadFixedSizedString(4);
                if (idCheck != "WEST")
                {
                    LogError("Not a valid TOC.");
                    return;
                }

                uint version = stream.ReadUInt32();
                LogInfo($"TOC version: 0x{version:X}");
                if (version < 0x16)
                {
                    LogError("Unsupported version " + version + " Expected >= 0x16.");
                    return;
                }

                //we have a valid TOC, let's initalise the file system
                string seperator = $"-";
                if (Directory.EnumerateFiles(installDir, "sdf-*-*.sdfdata").Count() < 1)
                {
                    seperator = $"_";
                }
                LogInfo($"Detected installDir: {installDir}");
                LogInfo($"Install part separator: '{seperator}'");
                SDFS fs = new SDFS();
                fs.LogInfo = LogInfo;
                fs.LogProgress = Console.WriteLine;
                fs.Initalise(stream, version, seperator, fileTableOffsetOverride, tocKey, tocIv);
                var partLangs = BuildInstallPartLanguageMap(installDir);
                LogInstallPartIds(fs, partLangs, LogInfo);
                if (listParts)
                {
                    PrintInstallPartIds(fs, partLangs);
                    return;
                }
                if (listDdsFlags)
                {
                    ListDdsFlagMismatches(fs, LogInfo, Console.WriteLine);
                    return;
                }

                IEnumerable<FileEntry> allEntries = fs.fileTable.fileEntries.Where(e => !string.IsNullOrEmpty(e.fileName));
                bool useLanguageFilter = !string.IsNullOrEmpty(language) && !allParts;
                string? langForResolve = useLanguageFilter ? language : null;
                if (useLanguageFilter)
                {
                    string langLower = language.ToLowerInvariant();
                    allEntries = allEntries.Where(e =>
                        !partLangs.TryGetValue(e.installPartId, out HashSet<string>? langs) ||
                        langs.Count == 0 ||
                        langs.Contains(langLower));
                }

                var entryList = allEntries.ToList();
                int totalFiles = entryList.Count;
                ulong totalBytes = 0;
                foreach (FileEntry entry in entryList)
                {
                    totalBytes += entry.decompressedSize;
                }
                LogInfo($"File entries: {totalFiles}");
                LogInfo($"Total bytes (entries sum): {totalBytes}");

                long processedFiles = 0;
                long processedBytes = 0;
                Stopwatch progressTimer = Stopwatch.StartNew();
                long lastReportMs = 0;
                object progressLock = new object();

                var groupedEntries = entryList
                    .GroupBy(e => e.fileName)
                    .Select(g => g.OrderBy(e => e.filePartoffset).ToList())
                    .ToList();

                int cacheCapacity = Math.Clamp(Environment.ProcessorCount * 2, 8, 64);
                using var streamCache = new FileStreamCache(cacheCapacity);

                ParallelOptions options = new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount
                };

                Parallel.ForEach(groupedEntries, options, entries =>
                {
                    string fileName = entries[0].fileName;
                    try
                    {
                        string outputFilePath = Path.Combine(dumpPath, fileName);
                        string? outputDir = Path.GetDirectoryName(outputFilePath);
                        if (!string.IsNullOrEmpty(outputDir))
                        {
                            Directory.CreateDirectory(outputDir);
                        }
                        else
                        {
                            Directory.CreateDirectory(dumpPath);
                        }

                    long expectedFileSize = GetExpectedFileSize(fs, entries);
                    int headerLen = 0;
                    FileEntry? headerEntry = entries.FirstOrDefault(e => e.isDDS && !e.isChunk) ?? entries.FirstOrDefault(e => e.isDDS);
                    if (headerEntry != null)
                    {
                        headerLen = GetDdsHeaderLength(fs, headerEntry);
                    }
                    LogDdsInfo(fs, entries, headerEntry, LogInfo);
                    long actualFileSize = 0;

                        using (var output = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.SequentialScan))
                        {
                            foreach (FileEntry fileEntry in entries)
                            {
                                byte[] fileData = fs.RequestFileData(fs, fileEntry, installDir, streamCache, langForResolve, LogInfo, LogError);
                                output.Write(fileData, 0, fileData.Length);
                                actualFileSize += fileData.Length;

                            bool isFirstChunk = !fileEntry.isChunk;
                            int chunkHeaderLen = isFirstChunk ? headerLen : 0;
                            long expectedChunkSize = (long)fileEntry.decompressedSize + chunkHeaderLen;
                            if (fileData.Length != expectedChunkSize)
                            {
                                LogError($"Size mismatch for chunk {fileEntry.fileName} partOffset=0x{fileEntry.filePartoffset:X}: expected {expectedChunkSize}, got {fileData.Length}");
                            }

                                long files = Interlocked.Increment(ref processedFiles);
                                long bytes = Interlocked.Add(ref processedBytes, (long)fileEntry.decompressedSize);
                                long elapsedMs = progressTimer.ElapsedMilliseconds;
                                if (elapsedMs - Interlocked.Read(ref lastReportMs) >= 1000)
                                {
                                    lock (progressLock)
                                    {
                                        if (elapsedMs - lastReportMs >= 1000)
                                        {
                                            double filePercent = totalFiles > 0 ? (files * 100.0) / totalFiles : 100.0;
                                            double bytePercent = totalBytes > 0 ? (bytes * 100.0) / totalBytes : 100.0;
                                            double mbDone = bytes / (1024.0 * 1024.0);
                                            double mbPerSec = mbDone / Math.Max(0.001, progressTimer.Elapsed.TotalSeconds);
                                            Console.WriteLine($"Progress: {files}/{totalFiles} files ({filePercent:0.0}%), {bytes}/{totalBytes} bytes ({bytePercent:0.0}%), {mbPerSec:0.0} MB/s");
                                            lastReportMs = elapsedMs;
                                        }
                                    }
                                }
                            }
                        }

                        long expectedFileSizeWithHeader = expectedFileSize + headerLen;
                        if (actualFileSize != expectedFileSizeWithHeader)
                        {
                            LogError($"Size mismatch for file {fileName}: expected {expectedFileSizeWithHeader}, got {actualFileSize}");
                        }
                    }
                    catch (Exception ex)
                    {
                        LogError($"Failed to extract {fileName}: {ex.Message}");
                    }
                });

                LogInfo("Finished!");
            }
        }

        private static string GetMagic(byte[] data)
        {
            if (data.Length < 4)
                return string.Empty;

            return System.Text.Encoding.ASCII.GetString(data, 0, 4);
        }

        private static bool TryDecompressToc(byte[] data, out byte[] output)
        {
            output = Array.Empty<byte>();

            if (Zlib.IsZlibHeader(data))
            {
                if (TryDecompressAndValidate(data, Zlib.Decompress, out output))
                    return true;
            }

            if (Lz4.IsLz4Frame(data))
            {
                if (TryDecompressAndValidate(data, Lz4.Decompress, out output))
                    return true;
            }

            if (Zstd.IsZstdFrame(data))
            {
                if (TryDecompressAndValidate(data, Zstd.Decompress, out output))
                    return true;
            }

            return false;
        }

        private static bool TryDecompressAndValidate(byte[] data, Func<byte[], byte[]> decompressor, out byte[] output)
        {
            output = Array.Empty<byte>();
            try
            {
                byte[] result = decompressor(data);
                if (GetMagic(result) != "WEST")
                    return false;

                output = result;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryParseOffset(string value, out long offset)
        {
            offset = 0;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return long.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out offset);
            }

            return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out offset);
        }

        private static byte[] ParseKeyMaterial(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return Array.Empty<byte>();

            string trimmed = value.Trim();
            if (trimmed.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
            {
                return ParseHexString(trimmed.Substring(4));
            }
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ParseHexString(trimmed.Substring(2));
            }

            return Encoding.UTF8.GetBytes(trimmed);
        }

        private static byte[] ParseHexString(string value)
        {
            string cleaned = value.Replace(" ", "", StringComparison.Ordinal)
                .Replace("_", "", StringComparison.Ordinal)
                .Replace("-", "", StringComparison.Ordinal)
                .Replace(":", "", StringComparison.Ordinal);

            if (cleaned.Length == 0)
                return Array.Empty<byte>();

            if ((cleaned.Length & 1) != 0)
                throw new ArgumentException("Hex string length must be even.");

            byte[] bytes = new byte[cleaned.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(cleaned.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            return bytes;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("SnowplowCLI usage:");
            Console.WriteLine("  SnowplowCLI <sdf.sdftoc> <outdir> [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --list-parts           List install part IDs and language tags, then exit.");
            Console.WriteLine("  --all-parts            Extract all parts (ignores --lang).");
            Console.WriteLine("  --lang <code>          Filter by language suffix (e.g. en-US).");
            Console.WriteLine("  -l <code>              Alias for --lang.");
            Console.WriteLine("  --offset <value>       Override file table offset (hex 0x.. or decimal).");
            Console.WriteLine("  --key <value>          TOC decryption key (string or hex:..).");
            Console.WriteLine("  --iv <value>           TOC decryption IV (string or hex:..).");
            Console.WriteLine("  --help, -h             Show this help.");
            Console.WriteLine();
            Console.WriteLine("Key/IV formats:");
            Console.WriteLine("  --key=hex:0011223344556677");
            Console.WriteLine("  --iv=0x8899AABBCCDDEEFF");
            Console.WriteLine("  --key=plain-text");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  SnowplowCLI sdf.sdftoc out --list-parts");
            Console.WriteLine("  SnowplowCLI sdf.sdftoc out --lang en-US");
            Console.WriteLine("  SnowplowCLI sdf.sdftoc out --key=hex:0011.. --iv=hex:AABB..");
        }

        private static Dictionary<ulong, HashSet<string>> BuildInstallPartLanguageMap(string? installDir)
        {
            var result = new Dictionary<ulong, HashSet<string>>();
            if (string.IsNullOrEmpty(installDir) || !Directory.Exists(installDir))
                return result;

            foreach (string file in Directory.EnumerateFiles(installDir, "sdf*.*", SearchOption.TopDirectoryOnly))
            {
                string name = Path.GetFileName(file);
                if (!TryParseInstallPartFileName(name, out ulong partId, out string? lang))
                    continue;

                if (!result.TryGetValue(partId, out HashSet<string>? langs))
                {
                    langs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    result[partId] = langs;
                }

                if (!string.IsNullOrEmpty(lang))
                {
                    langs.Add(lang.ToLowerInvariant());
                }
            }

            return result;
        }

        private static void LogInstallPartIds(SDFS fs, Dictionary<ulong, HashSet<string>> partLangs, Action<string> logInfo)
        {
            var ids = fs.fileTable.fileEntries.Select(e => e.installPartId).Distinct().OrderBy(id => id).ToList();
            logInfo($"InstallPart IDs in TOC ({ids.Count}): {string.Join(", ", ids)}");

            if (partLangs.Count == 0)
                return;

            foreach (var kvp in partLangs.OrderBy(k => k.Key))
            {
                if (kvp.Value.Count > 0)
                {
                    logInfo($"InstallPart {kvp.Key}: languages [{string.Join(", ", kvp.Value.OrderBy(v => v))}]");
                }
            }
        }

        private static void PrintInstallPartIds(SDFS fs, Dictionary<ulong, HashSet<string>> partLangs)
        {
            var ids = fs.fileTable.fileEntries.Select(e => e.installPartId).Distinct().OrderBy(id => id).ToList();
            Console.WriteLine($"InstallPart IDs in TOC ({ids.Count}): {string.Join(", ", ids)}");

            if (partLangs.Count == 0)
                return;

            foreach (var kvp in partLangs.OrderBy(k => k.Key))
            {
                if (kvp.Value.Count > 0)
                {
                    Console.WriteLine($"InstallPart {kvp.Key}: languages [{string.Join(", ", kvp.Value.OrderBy(v => v))}]");
                }
                else
                {
                    Console.WriteLine($"InstallPart {kvp.Key}: languages [none]");
                }
            }
        }

        private static bool TryParseInstallPartFileName(string fileName, out ulong partId, out string? language)
        {
            partId = 0;
            language = null;

            Match match = Regex.Match(fileName, @"^sdf[-_][A-Da-d][-_](\d{4})(?:[-_](.+))?\.sdfdata$", RegexOptions.CultureInvariant);
            if (!match.Success)
                return false;

            if (!ulong.TryParse(match.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out partId))
                return false;

            if (match.Groups.Count > 2)
            {
                string lang = match.Groups[2].Value;
                if (!string.IsNullOrWhiteSpace(lang))
                {
                    language = lang;
                }
            }

            return true;
        }

        private static int GetDdsHeaderLength(SDFS fs, FileEntry entry)
        {
            if (!fs.TryGetDdsHeaderBytes(entry, out byte[] header))
                return 0;

            return header.Length;
        }

        private static long GetExpectedFileSize(SDFS fs, List<FileEntry> entries)
        {
            long sum = 0;
            foreach (var entry in entries)
            {
                sum += (long)entry.decompressedSize;
            }
            return sum;
        }

        private static void ListDdsFlagMismatches(SDFS fs, Action<string> logInfo, Action<string> logProgress)
        {
            var groups = fs.fileTable.fileEntries
                .Where(e => !string.IsNullOrEmpty(e.fileName))
                .GroupBy(e => e.fileName)
                .Select(g => g.OrderBy(e => e.isChunk ? 1 : 0).First())
                .ToList();

            int total = 0;
            foreach (var entry in groups)
            {
                if (!entry.isDDS)
                    continue;

                string ext = Path.GetExtension(entry.fileName);
                if (!ext.Equals(".dds", StringComparison.OrdinalIgnoreCase))
                {
                    logInfo($"DDS flag on non-DDS file: {entry.fileName} ddsHeaderIndex={entry.ddsHeaderIndex} ddsType={entry.ddsType}");
                    total++;
                }
            }

            logProgress($"DDS flag mismatches: {total}");
        }

        private static void LogDdsInfo(SDFS fs, List<FileEntry> entries, FileEntry? headerEntry, Action<string> logInfo)
        {
            string fileName = entries[0].fileName;
            bool isDdsFile = fileName.EndsWith(".dds", StringComparison.OrdinalIgnoreCase) || entries.Any(e => e.isDDS);
            if (!isDdsFile)
                return;

            if (headerEntry != null && fs.TryGetDdsHeaderBytes(headerEntry, out byte[] headerBytes, out int resolvedIndex, out string matchKind))
            {
                bool hasMagic = headerBytes.Length >= 4 &&
                                headerBytes[0] == (byte)'D' &&
                                headerBytes[1] == (byte)'D' &&
                                headerBytes[2] == (byte)'S' &&
                                headerBytes[3] == (byte)' ';
                bool isDx10 = headerBytes.Length >= 88 &&
                              headerBytes[84] == (byte)'D' &&
                              headerBytes[85] == (byte)'X' &&
                              headerBytes[86] == (byte)'1' &&
                              headerBytes[87] == (byte)'0';
                logInfo($"DDS file: {fileName} headerIndex={headerEntry.ddsHeaderIndex} ddsType={headerEntry.ddsType} resolvedIndex={resolvedIndex} match={matchKind} headerLen=0x{headerBytes.Length:X} dx10={(isDx10 ? "yes" : "no")} magic={(hasMagic ? "yes" : "no")}");
            }
            else
            {
                ulong index = headerEntry?.ddsHeaderIndex ?? 0;
                ulong ddsType = headerEntry?.ddsType ?? 0;
                int headerCount = fs.ddsHeaders?.Length ?? 0;
                string hasFlag = entries.Any(e => e.isDDS) ? "yes" : "no";
                logInfo($"DDS file: {fileName} headerAvailable=no headerIndex={index} ddsType={ddsType} headersCount={headerCount} hasDDSFlag={hasFlag}");
            }
        }
    }
}
