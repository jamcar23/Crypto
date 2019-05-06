using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using CryptoNI.Utils;

namespace CryptoNI.AesNI
{
    internal sealed class Aes128Key : AesKey
    {
        private const int NumberOfRoundKeys = 10;
        private readonly byte[] _expandedKey = new byte[2 * BytesPerRoundKey * NumberOfRoundKeys];

        public override ReadOnlySpan<byte> ExpandedKey => _expandedKey;

        internal Aes128Key(ReadOnlySpan<byte> key)
        {
            KeyExpansion(key, _expandedKey);
        }

        private static void KeyExpansion(ReadOnlySpan<byte> key, Span<byte> keySchedule)
        {
            ref byte keyRef = ref MemoryMarshal.GetReference(key);
            ref byte expKey = ref MemoryMarshal.GetReference(keySchedule);

            Vector128<byte> tmp = MemUtils.ReadUnaligned(ref keyRef);
            MemUtils.WriteUnalignedOffset(ref expKey,  0 * BytesPerRoundKey, tmp);

            tmp = Aes128KeyExp(tmp, 0x01);
            MemUtils.WriteUnalignedOffset(ref expKey,  1 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  19 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x02);
            MemUtils.WriteUnalignedOffset(ref expKey,  2 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  18 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x04);
            MemUtils.WriteUnalignedOffset(ref expKey,  3 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  17 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x08);
            MemUtils.WriteUnalignedOffset(ref expKey,  4 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  16 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x10);
            MemUtils.WriteUnalignedOffset(ref expKey,  5 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  15 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x20);
            MemUtils.WriteUnalignedOffset(ref expKey,  6 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  14 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x40);
            MemUtils.WriteUnalignedOffset(ref expKey,  7 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  13 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x80);
            MemUtils.WriteUnalignedOffset(ref expKey,  8 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  12 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x1B);
            MemUtils.WriteUnalignedOffset(ref expKey,  9 * BytesPerRoundKey, tmp);
            MemUtils.WriteUnalignedOffset(ref expKey,  11 * BytesPerRoundKey,
                Aes.InverseMixColumns(tmp));
            
            tmp = Aes128KeyExp(tmp, 0x36);
            MemUtils.WriteUnalignedOffset(ref expKey,  10 * BytesPerRoundKey, tmp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes128KeyExp(Vector128<byte> key, byte rcon)
        {
            Vector128<byte> tmp = Aes.KeygenAssist(key, rcon);
            tmp = Sse2.Shuffle(tmp.AsInt32(), 0xFF).AsByte();
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));

            return Sse2.Xor(key, tmp);
        }
    }
}