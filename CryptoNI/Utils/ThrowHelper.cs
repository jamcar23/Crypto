using System;
using System.Runtime.CompilerServices;

namespace CryptoNI.Utils
{
    public static class ThrowHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowUnknownKeySizeException(string argument, int keyLength) 
            => throw new ArgumentOutOfRangeException(argument, $"Key size not supported: ${keyLength}");
    }
}