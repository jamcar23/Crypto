using System;
using System.Runtime.CompilerServices;

namespace CryptoNI.Utils
{
    public static class ThrowHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowUnknownKeySizeException(string argument, int keyLength) 
            => throw new ArgumentOutOfRangeException(argument, $"Key size not supported: {keyLength}");
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowNotMultipleOfBlockSizeException(string argument, int size) 
            => throw new ArgumentOutOfRangeException(argument, 
                $"Buffer length not a multiple of the block size: {size}");
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowDestinationBufferTooSmallException(string argument) 
            => throw new ArgumentOutOfRangeException(argument, "Destination buffer too small");
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowArgumentNullException(string argument) => throw new ArgumentNullException(argument);
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowNotImplementedException() => throw new NotImplementedException();
    }
}