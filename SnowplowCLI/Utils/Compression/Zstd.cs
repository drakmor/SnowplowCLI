using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnowplowCLI.Utils.Compression
{
    public class Zstd
    {
        public static byte[] Decompress(byte[] b)
        {
            using (var decompressor = new ZstdNet.Decompressor())
            {
                return decompressor.Unwrap(b);
            }
        }

        public static bool IsZstdFrame(ReadOnlySpan<byte> data)
        {
            if (data.Length < 4)
                return false;

            uint sig = BitConverter.ToUInt32(data);
            return sig == 0xFD2FB528 || sig == 0xDFF25B82;
        }
    }
}
