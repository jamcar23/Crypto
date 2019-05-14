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
        internal static Vector128<byte> ReadUnalignedOffset(ref byte source, int offset) =>
            Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref source, (IntPtr) offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteUnalignedOffset(ref byte target, int offset, Vector128<byte> value) =>
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref target, (IntPtr) offset), value);
    }
}