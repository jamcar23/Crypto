using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace CryptoNI.Utils
{
    internal static class MemUtils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Vector128<byte> ReadUnaligned(ref byte source) =>
            Unsafe.ReadUnaligned<Vector128<byte>>(ref source);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteUnalignedOffset(ref byte target, IntPtr offset, Vector128<byte> value) =>
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref target, offset), value);
    }
}