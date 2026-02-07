using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SnowplowCLI.Utils.Compression
{
    public class Zlib
    {
        public static byte[] Decompress(byte[] i)
        {
            using (var input = new MemoryStream(i))
            using (var zlib = new ZLibStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                zlib.CopyTo(output);
                return output.ToArray();
            }
        }

        public static bool IsZlibHeader(ReadOnlySpan<byte> data)
        {
            if (data.Length < 2)
                return false;

            byte cmf = data[0];
            byte flg = data[1];

            if ((cmf & 0x0F) != 8) // deflate
                return false;

            int header = (cmf << 8) | flg;
            return header % 31 == 0;
        }
    }
}
