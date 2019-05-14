using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using CryptoNI.Utils;

namespace CryptoNI.AesNI
{
    /// <summary>
    /// <para>
    /// Implements AES using hardware intrinsics.
    ///
    /// Currently only support 128 or 256 bit keys using CBC mode
    /// </para>
    /// <para>
    /// AES reference:
    ///     https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
    /// </para>
    /// 
    /// <para>
    /// x86/x64 reference:
    ///     https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
    /// </para>
    ///
    /// <para>
    /// Fast reference:
    ///     http://www.rksm.me/papers/rmanley-indocrypt10.pdf
    /// </para>
    /// </summary>
    public static class AES
    {
        private const int BytesPerRoundKey = 16;
        private const int BlockSize = 16;

        #region Encryption

        /// <summary>
        /// Encrypts some plaintext data into the ciphertext buffer, using a 128 or 256 bit key.
        /// 
        /// NOTE: the plaintext data must be padded before calling this.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        public static void Encrypt(ReadOnlySpan<byte> plainText, Span<byte> cipherText, AesKey key, 
            ReadOnlySpan<byte> iv)
        {
            if (plainText.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(nameof(plainText));
            }

            if (plainText.Length % BlockSize != 0)
            {
                ThrowHelper.ThrowNotMultipleOfBlockSizeException(nameof(plainText), BlockSize);
            }

            if (iv.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(nameof(iv));
            }

            if (cipherText.Length % BlockSize != 0)
            {
                ThrowHelper.ThrowNotMultipleOfBlockSizeException(nameof(cipherText), BlockSize);
            }
            
            if (cipherText.Length < plainText.Length)
            {
                ThrowHelper.ThrowDestinationBufferTooSmallException(nameof(cipherText));
            }

            switch (key)
            {
                case Aes128Key k:
                    Encrypt(plainText, cipherText, k, iv);
                    break;
                default:
                    ThrowHelper.ThrowNotImplementedException();
                    break;
            }
        }

        private static void Encrypt(ReadOnlySpan<byte> plainText, Span<byte> cipherText, Aes128Key key,
            ReadOnlySpan<byte> iv)
        {
            ref byte expKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref byte inRef = ref MemoryMarshal.GetReference(plainText);
            ref byte outRef = ref MemoryMarshal.GetReference(cipherText);
            ref byte ivRef = ref MemoryMarshal.GetReference(iv);

            int left = plainText.Length;

            Vector128<byte> k0 = MemUtils.ReadUnaligned(ref expKey);
            Vector128<byte> k1 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 1);
            Vector128<byte> k2 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 2);
            Vector128<byte> k3 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 3);
            Vector128<byte> k4 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 4);
            Vector128<byte> k5 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 5);
            Vector128<byte> k6 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 6);
            Vector128<byte> k7 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 7);
            Vector128<byte> k8 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 8);
            Vector128<byte> k9 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 9);
            Vector128<byte> k10 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 10);

            Vector128<byte> feedBack = MemUtils.ReadUnaligned(ref ivRef);
            Vector128<byte> block;

            while (left > 0)
            {
                block = MemUtils.ReadUnaligned(ref inRef);
                
                feedBack = Sse2.Xor(block, feedBack);
                feedBack = Sse2.Xor(feedBack, k0);

                feedBack = Aes.Encrypt(feedBack, k1);
                feedBack = Aes.Encrypt(feedBack, k2);
                feedBack = Aes.Encrypt(feedBack, k3);
                feedBack = Aes.Encrypt(feedBack, k4);
                feedBack = Aes.Encrypt(feedBack, k5);
                feedBack = Aes.Encrypt(feedBack, k6);
                feedBack = Aes.Encrypt(feedBack, k7);
                feedBack = Aes.Encrypt(feedBack, k8);
                feedBack = Aes.Encrypt(feedBack, k9);
                feedBack = Aes.EncryptLast(feedBack, k10);
                
                Unsafe.WriteUnaligned(ref outRef, feedBack);

                inRef = ref Unsafe.AddByteOffset(ref inRef, (IntPtr) BlockSize);
                outRef = ref Unsafe.AddByteOffset(ref outRef, (IntPtr) BlockSize);
                left -= BlockSize;
            }
        }

        #endregion

        #region Decryption

        public static void Decrypt(Span<byte> plainText, ReadOnlySpan<byte> cipherText, AesKey key, 
            ReadOnlySpan<byte> iv)
        {
            if (cipherText.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(nameof(cipherText));
            }

            if (cipherText.Length % BlockSize != 0)
            {
                ThrowHelper.ThrowNotMultipleOfBlockSizeException(nameof(cipherText), BlockSize);
            }

            if (iv.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(nameof(iv));
            }

            switch (key)
            {
                case Aes128Key k:
                    Decrypt(plainText, cipherText, k, iv);
                    break;
                default:
                    ThrowHelper.ThrowNotImplementedException();
                    break;
            }
        }

        private static void Decrypt(Span<byte> plainText, ReadOnlySpan<byte> cipherText, Aes128Key key,
            ReadOnlySpan<byte> iv)
        {
            ref byte expKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref byte inRef = ref MemoryMarshal.GetReference(cipherText);
            ref byte outRef = ref MemoryMarshal.GetReference(plainText);
            ref byte ivRef = ref MemoryMarshal.GetReference(iv);

            int left = cipherText.Length;

            Vector128<byte> k0 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 10);
            Vector128<byte> k1 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 11);
            Vector128<byte> k2 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 12);
            Vector128<byte> k3 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 13);
            Vector128<byte> k4 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 14);
            Vector128<byte> k5 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 15);
            Vector128<byte> k6 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 16);
            Vector128<byte> k7 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 17);
            Vector128<byte> k8 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 18);
            Vector128<byte> k9 = MemUtils.ReadUnalignedOffset(ref expKey, BytesPerRoundKey * 19);
            Vector128<byte> k10 = MemUtils.ReadUnaligned(ref expKey);

            Vector128<byte> feedBack = MemUtils.ReadUnaligned(ref ivRef);
            Vector128<byte> block, lastIn, data;

            while (left > 0)
            {
                block = MemUtils.ReadUnaligned(ref inRef);
                lastIn = block;
                data = Sse2.Xor(lastIn, k0);

                data = Aes.Decrypt(data, k1);
                data = Aes.Decrypt(data, k2);
                data = Aes.Decrypt(data, k3);
                data = Aes.Decrypt(data, k4);
                data = Aes.Decrypt(data, k5);
                data = Aes.Decrypt(data, k6);
                data = Aes.Decrypt(data, k7);
                data = Aes.Decrypt(data, k8);
                data = Aes.Decrypt(data, k9);
                data = Aes.DecryptLast(data, k10);
                
                data = Sse2.Xor(data, feedBack);
                
                Unsafe.WriteUnaligned(ref outRef, data);

                feedBack = lastIn;

                inRef = ref Unsafe.AddByteOffset(ref inRef, (IntPtr) BlockSize);
                outRef = ref Unsafe.AddByteOffset(ref outRef, (IntPtr) BlockSize);
                left -= BlockSize;
            }
        }

        #endregion
    }
}