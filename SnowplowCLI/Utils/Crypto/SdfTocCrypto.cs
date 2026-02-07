using System;
using System.Security.Cryptography;

namespace SnowplowCLI.Utils.Crypto
{
    public static class SdfTocCrypto
    {
        private static readonly uint[] TeaKey = { 0x0B, 0x11, 0x17, 0x1F };
        private static readonly byte[] ByteMap = BuildByteMap();

        public static void DecryptInPlace(byte[] buffer, byte[] keyText, byte[] ivText)
        {
            if (buffer.Length == 0)
                return;

            ApplyTeaHeader(buffer);

            byte[] keyBytes = DeriveKeyBytes(keyText);
            byte[] ivBytes = DeriveKeyBytes(ivText);

            PcbcDecrypt(buffer, keyBytes, ivBytes);
        }

        private static void ApplyTeaHeader(byte[] buffer)
        {
            if (buffer.Length < 8)
                return;

            uint v4 = ReadUInt32LE(buffer, 0);
            uint v5 = ReadUInt32LE(buffer, 4);
            const uint delta = 0x61C88647;
            uint sum = 0x28B7BD67;

            unchecked
            {
                for (int i = 0; i < 32; i++)
                {
                    uint keyIndex = (sum - delta) >> 11;
                    v5 -= (v4 + ((v4 << 4) ^ (v4 >> 5))) ^ (TeaKey[keyIndex & 3] + sum - delta);
                    uint v8 = sum + TeaKey[sum & 3];
                    sum += delta;
                    v4 -= (v5 + ((v5 << 4) ^ (v5 >> 5))) ^ v8;
                }
            }

            WriteUInt32LE(buffer, 0, v4);
            WriteUInt32LE(buffer, 4, v5);
        }

        private static byte[] DeriveKeyBytes(ReadOnlySpan<byte> text)
        {
            byte[] key = new byte[8];

            for (int i = 0; i < text.Length; i++)
            {
                byte value = text[i];
                int index = i & 7;
                if ((i & 8) != 0)
                {
                    byte rotated = Rol(value, 4);
                    index ^= 7;
                    byte v8 = (byte)(((rotated & 0x33) << 2) | ((rotated >> 2) & 0x33));
                    byte v9 = (byte)(((v8 & 0x55) << 1) | ((v8 >> 1) & 0x55));
                    key[index] ^= v9;
                }
                else
                {
                    key[index] ^= (byte)(value << 1);
                }
            }

            MapBytes(key);
            key = ComputeMac(text, key);
            MapBytes(key);

            return key;
        }

        private static byte[] ComputeMac(ReadOnlySpan<byte> input, byte[] keyBytes)
        {
            if (input.Length == 0)
                return (byte[])keyBytes.Clone();

            uint v0 = ReadUInt32LE(keyBytes, 0);
            uint v1 = ReadUInt32LE(keyBytes, 4);

            using DES des = DES.Create();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.Key = (byte[])keyBytes.Clone();
            des.IV = new byte[8];
            using ICryptoTransform encryptor = des.CreateEncryptor();

            byte[] block = new byte[8];
            byte[] outBlock = new byte[8];

            int offset = 0;
            while (offset < input.Length)
            {
                int remaining = input.Length - offset;
                int take = Math.Min(8, remaining);
                Array.Clear(block, 0, block.Length);
                input.Slice(offset, take).CopyTo(block);

                uint b0 = ReadUInt32LE(block, 0);
                uint b1 = ReadUInt32LE(block, 4);

                b0 ^= v0;
                b1 ^= v1;

                WriteUInt32LE(block, 0, b0);
                WriteUInt32LE(block, 4, b1);

                encryptor.TransformBlock(block, 0, 8, outBlock, 0);
                v0 = ReadUInt32LE(outBlock, 0);
                v1 = ReadUInt32LE(outBlock, 4);

                offset += 8;
            }

            byte[] result = new byte[8];
            WriteUInt32LE(result, 0, v0);
            WriteUInt32LE(result, 4, v1);
            return result;
        }

        private static void PcbcDecrypt(byte[] buffer, byte[] keyBytes, byte[] ivBytes)
        {
            int length = buffer.Length;
            int aligned = (length + 7) & ~7;
            byte[] work = buffer;

            if (aligned != length)
            {
                work = new byte[aligned];
                Buffer.BlockCopy(buffer, 0, work, 0, length);
            }

            uint prev0 = ReadUInt32LE(ivBytes, 0);
            uint prev1 = ReadUInt32LE(ivBytes, 4);

            using DES des = DES.Create();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.Key = (byte[])keyBytes.Clone();
            des.IV = new byte[8];
            using ICryptoTransform decryptor = des.CreateDecryptor();

            byte[] block = new byte[8];
            byte[] outBlock = new byte[8];

            for (int offset = 0; offset < aligned; offset += 8)
            {
                Buffer.BlockCopy(work, offset, block, 0, 8);
                uint c0 = ReadUInt32LE(block, 0);
                uint c1 = ReadUInt32LE(block, 4);

                decryptor.TransformBlock(block, 0, 8, outBlock, 0);
                uint d0 = ReadUInt32LE(outBlock, 0);
                uint d1 = ReadUInt32LE(outBlock, 4);

                uint p0 = d0 ^ prev0;
                uint p1 = d1 ^ prev1;

                WriteUInt32LE(work, offset, p0);
                WriteUInt32LE(work, offset + 4, p1);

                prev0 = p0 ^ c0;
                prev1 = p1 ^ c1;
            }

            if (!ReferenceEquals(work, buffer))
            {
                Buffer.BlockCopy(work, 0, buffer, 0, length);
            }
        }

        private static void MapBytes(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = ByteMap[key[i]];
            }
        }

        private static byte Rol(byte value, int bits)
        {
            return (byte)((value << bits) | (value >> (8 - bits)));
        }

        private static uint ReadUInt32LE(ReadOnlySpan<byte> data, int offset)
        {
            return (uint)(data[offset]
                | (data[offset + 1] << 8)
                | (data[offset + 2] << 16)
                | (data[offset + 3] << 24));
        }

        private static void WriteUInt32LE(Span<byte> data, int offset, uint value)
        {
            data[offset] = (byte)(value & 0xFF);
            data[offset + 1] = (byte)((value >> 8) & 0xFF);
            data[offset + 2] = (byte)((value >> 16) & 0xFF);
            data[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static byte[] BuildByteMap()
        {
            byte[] values =
            {
                0x01, 0x02, 0x04, 0x07, 0x08, 0x0B, 0x0D, 0x0E,
                0x10, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F,
                0x20, 0x23, 0x25, 0x26, 0x29, 0x2A, 0x2C, 0x2F,
                0x31, 0x32, 0x34, 0x37, 0x38, 0x3B, 0x3D, 0x3E,
                0x40, 0x43, 0x45, 0x46, 0x49, 0x4A, 0x4C, 0x4F,
                0x51, 0x52, 0x54, 0x57, 0x58, 0x5B, 0x5D, 0x5E,
                0x61, 0x62, 0x64, 0x67, 0x68, 0x6B, 0x6D, 0x6E,
                0x70, 0x73, 0x75, 0x76, 0x79, 0x7A, 0x7C, 0x7F,
                0x80, 0x83, 0x85, 0x86, 0x89, 0x8A, 0x8C, 0x8F,
                0x91, 0x92, 0x94, 0x97, 0x98, 0x9B, 0x9D, 0x9E,
                0xA1, 0xA2, 0xA4, 0xA7, 0xA8, 0xAB, 0xAD, 0xAE,
                0xB0, 0xB3, 0xB5, 0xB6, 0xB9, 0xBA, 0xBC, 0xBF,
                0xC1, 0xC2, 0xC4, 0xC7, 0xC8, 0xCB, 0xCD, 0xCE,
                0xD0, 0xD3, 0xD5, 0xD6, 0xD9, 0xDA, 0xDC, 0xDF,
                0xE0, 0xE3, 0xE5, 0xE6, 0xE9, 0xEA, 0xEC, 0xEF,
                0xF1, 0xF2, 0xF4, 0xF7, 0xF8, 0xFB, 0xFD, 0xFE
            };

            if (values.Length != 128)
                throw new InvalidOperationException("Byte map length mismatch.");

            byte[] map = new byte[256];
            for (int i = 0; i < values.Length; i++)
            {
                map[i * 2] = values[i];
                map[i * 2 + 1] = values[i];
            }
            return map;
        }
    }
}
