using System;
using System.Runtime.CompilerServices;
using CryptoNI.Utils;

namespace CryptoNI.AesNI
{
    public abstract class AesKey
    {
        public const int BytesPerRoundKey = 16;

        public abstract ReadOnlySpan<byte> ExpandedKey { get; } // todo make internal

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static AesKey Create(Span<byte> key)
        {
            switch (key.Length)
            {
                case 16:
                    return new Aes128Key(key);
                default:
                    ThrowHelper.ThrowUnknownKeySizeException(nameof(key), key.Length);
                    return null;
            }
        }
    }
}