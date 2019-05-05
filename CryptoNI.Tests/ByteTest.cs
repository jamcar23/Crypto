using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using CryptoNI.Utils;
using NUnit.Framework;

namespace CryptoNI.Tests
{
    /// <summary>
    /// Test cases for things related to bytes and bits. 
    /// </summary>
    public static class ByteTest
    {
        [Test]
        public static void ByteOrderReversalTest()
        {
            uint start = 0x2B7E1516;
            uint startReverse = 0x16157E2B;

            uint r = ByteUtils.ReverseBytes(start);
            Assert.AreEqual(startReverse, r, "Failed to reverse starting value.");
            Assert.AreEqual(start, ByteUtils.ReverseBytes(r), "Failed to reverse back to starting value");
        }

        
    }
}