using System;
using System.Text;

namespace Hash_SHA_256
{
    internal class SHA256
    {
        private static readonly uint[] K = new uint[]
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private static readonly uint[] H = new uint[]
        {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        public static string ComputeSHA256(string input)
        {
            byte[] message = Encoding.UTF8.GetBytes(input);
            uint[] hash = (uint[])H.Clone();
            byte[] paddedMessage = PadMessage(message);
            int blocks = paddedMessage.Length / 64;

            for (int i = 0; i < blocks; i++)
            {
                uint[] w = new uint[64];
                for (int j = 0; j < 16; j++)
                {
                    w[j] = BitConverter.ToUInt32(paddedMessage, (i * 64) + (j * 4));
                    w[j] = SwapEndian(w[j]);
                }

                for (int j = 16; j < 64; j++)
                {
                    uint s0 = RotateRight(w[j - 15], 7) ^ RotateRight(w[j - 15], 18) ^ (w[j - 15] >> 3);
                    uint s1 = RotateRight(w[j - 2], 17) ^ RotateRight(w[j - 2], 19) ^ (w[j - 2] >> 10);
                    w[j] = w[j - 16] + s0 + w[j - 7] + s1;
                }

                uint a = hash[0], b = hash[1], c = hash[2], d = hash[3];
                uint e = hash[4], f = hash[5], g = hash[6], h = hash[7];

                for (int j = 0; j < 64; j++)
                {
                    uint s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
                    uint ch = (e & f) ^ (~e & g);
                    uint temp1 = h + s1 + ch + K[j] + w[j];
                    uint s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint temp2 = s0 + maj;

                    h = g; g = f; f = e; e = d + temp1;
                    d = c; c = b; b = a; a = temp1 + temp2;
                }

                hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
                hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
            }

            StringBuilder sb = new StringBuilder();
            foreach (uint hVal in hash) sb.Append(hVal.ToString("x8"));
            return sb.ToString();
        }

        public static byte[] ComputeSHA256Bytes(string input)
        {
            byte[] message = Encoding.UTF8.GetBytes(input);
            uint[] hash = (uint[])H.Clone();
            byte[] paddedMessage = PadMessage(message);
            int blocks = paddedMessage.Length / 64;

            for (int i = 0; i < blocks; i++)
            {
                uint[] w = new uint[64];
                for (int j = 0; j < 16; j++)
                {
                    w[j] = BitConverter.ToUInt32(paddedMessage, (i * 64) + (j * 4));
                    w[j] = SwapEndian(w[j]);
                }

                for (int j = 16; j < 64; j++)
                {
                    uint s0 = RotateRight(w[j - 15], 7) ^ RotateRight(w[j - 15], 18) ^ (w[j - 15] >> 3);
                    uint s1 = RotateRight(w[j - 2], 17) ^ RotateRight(w[j - 2], 19) ^ (w[j - 2] >> 10);
                    w[j] = w[j - 16] + s0 + w[j - 7] + s1;
                }

                uint a = hash[0], b = hash[1], c = hash[2], d = hash[3];
                uint e = hash[4], f = hash[5], g = hash[6], h = hash[7];

                for (int j = 0; j < 64; j++)
                {
                    uint S1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
                    uint ch = (e & f) ^ (~e & g);
                    uint temp1 = h + S1 + ch + K[j] + w[j];
                    uint S0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint temp2 = S0 + maj;

                    h = g; g = f; f = e; e = d + temp1;
                    d = c; c = b; b = a; a = temp1 + temp2;
                }

                hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
                hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
            }
            return ConvertHashToBytes(hash);

        }

        public static byte[] ConvertHashToBytes(uint[] hash)
        {
            byte[] result = new byte[hash.Length * 4];
            for (int i = 0; i < hash.Length; i++)
            {
                byte[] bytes = BitConverter.GetBytes(SwapEndian(hash[i]));
                Array.Copy(bytes, 0, result, i * 4, 4);
            }
            return result;
        }



        private static byte[] PadMessage(byte[] message)
        {
            int originalLength = message.Length;
            int paddingLength = (56 - (originalLength + 1) % 64) % 64;
            long messageLengthBits = (long)originalLength * 8;
            byte[] paddedMessage = new byte[originalLength + paddingLength + 9];
            Array.Copy(message, paddedMessage, originalLength);
            paddedMessage[originalLength] = 0x80;
            for (int i = 0; i < 8; i++)
                paddedMessage[paddedMessage.Length - 8 + i] = (byte)((messageLengthBits >> (8 * (7 - i))) & 0xFF);
            return paddedMessage;
        }

        private static uint RotateRight(uint x, int n) => (x >> n) | (x << (32 - n));
        private static uint SwapEndian(uint x) => ((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000);
    }
}
