using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace CryptoNI.Extensions
{
    public static class SpanExtensions
    {
        public static void ReverseElement<T>(this Span<T> span)
        {
            int l = span.Length;

            if (l % 2 != 0)
            {
                
            }
        }
    }
}