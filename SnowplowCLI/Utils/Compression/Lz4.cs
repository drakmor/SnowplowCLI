using K4os.Compression.LZ4.Streams;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SnowplowCLI.Utils.Compression
{
    public class Lz4
    {
        public static byte[] Decompress(byte[] i)
        {
            using (var input = new MemoryStream(i))
            using (var source = LZ4Stream.Decode(input))
            using (var output = new MemoryStream())
            {
                source.CopyTo(output);
                return output.ToArray();
            }
        }

        public static bool IsLz4Frame(ReadOnlySpan<byte> data)
        {
            if (data.Length < 4)
                return false;

            uint sig = BitConverter.ToUInt32(data);
            return sig == 0x184D2204;
        }
    }
}
