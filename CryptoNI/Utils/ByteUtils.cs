using System;
using System.Runtime.CompilerServices;

namespace CryptoNI.Utils
{
    public static class ByteUtils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static ushort ReverseBytes(ushort x)
        {
            return (ushort)((x & 0xFFU) << 8 | (x & 0xFF00U) >> 8);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static uint ReverseBytes(uint x)
        {
            return (x & 0x000000FFU) << 24 | (x & 0x0000FF00U) << 8 |
                   (x & 0x00FF0000U) >> 8 | (x & 0xFF000000U) >> 24;
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static ulong ReverseBytes(ulong x)
        {
            return (x & 0x00000000000000FFUL) << 56 | (x & 0x000000000000FF00UL) << 40 |
                   (x & 0x0000000000FF0000UL) << 24 | (x & 0x00000000FF000000UL) << 8 |
                   (x & 0x000000FF00000000UL) >> 8 | (x & 0x0000FF0000000000UL) >> 24 |
                   (x & 0x00FF000000000000UL) >> 40 | (x & 0xFF00000000000000UL) >> 56;
        }
        
        public static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            hex = hex.ToUpper();
            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int v = (int)hex;

            return v - (v < 58 ? 48 : 55);
        }
    }
}