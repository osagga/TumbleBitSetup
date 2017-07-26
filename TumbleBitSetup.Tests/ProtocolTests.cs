﻿using Org.BouncyCastle.Math;
using System;
using System.Linq;
using Org.BouncyCastle.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TumbleBitSetup.Tests
{
    [TestClass()]
    public class UtilsTests
    {
        [TestMethod()]
        public void Int_I2OSP_Test()
        {
            // Test if we can encode and decode successfully (Int Type).
            int size = Utils.GetOctetLen(10000);

            for (int i = 0; i < 10000; i++)
            {
                byte[] encoded = Utils.I2OSP(i, size);
                int decoded = Utils.OS2IP(encoded).IntValue;

                Assert.AreEqual(decoded, i);
            }

        }

        [TestMethod()]
        public void BigInt_I2OSP_Test()
        {
            // Test if we can encode and decode successfully (BigInteger Type).
            int size = Utils.GetByteLength(50);
            for (int i = 100; i < 10000; i++)
            {
                var randInt = TestUtils.GenRandomInt(50, true, false);
                byte[] encoded = Utils.I2OSP(randInt, size);
                BigInteger decoded = Utils.OS2IP(encoded);

                Assert.AreEqual(decoded, randInt);
            }

        }

        [TestMethod()]
        [ExpectedException(typeof(ArithmeticException))]
        public void I2OSP_Test1()
        {
            // Test if size is smaller than needed.
            // Should give a ArithmeticException.
            int x = 99999999;
            int size = 1;
            Utils.I2OSP(x, size);
        }

        [TestMethod()]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void I2OSP_Test2()
        {
            // Test if the integer is negative
            // Should give a ArgumentOutOfRangeException.
            int x = -1;
            int size = 42;
            Utils.I2OSP(x, size);
        }

        [TestMethod()]
        public void PrimesTest()
        {
            // confirm that the output of TestUtils.Prime(A) is the prefix of the output of TestUtils.Prime(B), where B >> A
            for (int i = 100; i < 200; i++)
            {
                var smallPrimeList = Utils.Primes(i).ToList();
                var largePrimeList = Utils.Primes(i + 1).ToList();
                Assert.IsTrue(TestUtils.isSubset(smallPrimeList, largePrimeList));
            }
        }

        [TestMethod()]
        public void MGF1_SHA256_Test()
        {
            var data1 = Strings.ToByteArray("TEST42");
            var data2 = Strings.ToByteArray("TEST222");
            var keySize = 42;
            var keySizeBytes = Utils.GetByteLength(keySize);

            var output1 = Utils.MGF1_SHA256(data1, keySize);
            var output11 = Utils.MGF1_SHA256(data1, keySize);
            var output2 = Utils.MGF1_SHA256(data2, keySize);

            // Test that the length is correct
            Assert.AreEqual(output1.Length, keySizeBytes);
            // Test that the same input gives the same output
            Assert.IsTrue(output11.SequenceEqual(output1));
            // Test that the two output are different
            Assert.IsFalse(output1.SequenceEqual(output2));
        }

        [TestMethod()]
        public void CombineTest()
        {
            var data1 = Strings.ToByteArray("Tumble");
            var data2 = Strings.ToByteArray("Bit");

            byte[] combined = Utils.Combine(data1, data2);
            var combinedString = Strings.FromByteArray(combined);
            // Check the length
            Assert.IsTrue(combined.Length == (data1.Length + data2.Length));
            // Check the integrity
            Assert.IsTrue(combinedString.Equals("TumbleBit"));
        }

        [TestMethod()]
        public void GetOctetLenTest()
        {
            // TODO: Not really is these tests are enough
            int x = 255; // this is 0xff, so it should give 1
            int y = 256; // this is 0x100, so it should give 2
            var xLen = Utils.GetOctetLen(x);
            var yLen = Utils.GetOctetLen(y);
            Assert.IsTrue(xLen.Equals(1));
            Assert.IsTrue(yLen.Equals(2));

        }

        [TestMethod()]
        public void SHA256_Test()
        {
            var data1 = Strings.ToByteArray("TEST42");
            var data2 = Strings.ToByteArray("TEST22");

            var output1 = Utils.SHA256(data1);
            var output11 = Utils.SHA256(data1);
            var output2 = Utils.SHA256(data2);

            // Test that the length is correct
            Assert.AreEqual(output1.Length, 32);
            // Test that the same input gives the same output
            Assert.IsTrue(output11.SequenceEqual(output1));
            // Test that the two output are different
            Assert.IsFalse(output1.SequenceEqual(output2));
        }

        [TestMethod()]
        public void TruncateToKbitsTest()
        {
            var data = Strings.ToByteArray("AABBCCDD424242");
            // Take the first 8 characters (64 bits)
            var trunk = Utils.TruncateToKbits(data, 64);
            var trunkStirng = Strings.FromByteArray(trunk);

            Assert.IsTrue(trunkStirng.Equals("AABBCCDD"));
        }
        [TestMethod()]
        public void GetByteLengthTest()
        {
            // 0 bits need 0 bytes
            Assert.IsTrue(Utils.GetByteLength(0).Equals(0));
            // 1 bit needs 1 byte
            Assert.IsTrue(Utils.GetByteLength(1).Equals(1));
            // 7 bits need 1 byte
            Assert.IsTrue(Utils.GetByteLength(7).Equals(1));
            // 8 bits need 1 byte
            Assert.IsTrue(Utils.GetByteLength(8).Equals(1));
            // 9 bits need 2 byte
            Assert.IsTrue(Utils.GetByteLength(9).Equals(2));
        }
    }

    [TestClass()]
    public class PermutationTestProtocolTests
    {
        public int iterValid = 1; // Number of iterations for a valid test
        public int iterInValid = 1; // Number of iterations for an invalid test

        int alpha = 41;
        BigInteger Exp = BigInteger.Three;
        public byte[] ps = Strings.ToByteArray("public string");

        [TestMethod()]
        public void ProvingAndVerifyingTest()
        {
            // repeating the test "iterValid" times
            // TODO: Different k test?
            for (int i = 0; i < iterValid; i++)
            {
                Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 4096, alpha));
                Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 2048, alpha));
                Assert.IsTrue(_ProvingAndVerifyingTest(new BigInteger("65537"), 2048, 7649)); // Case where m1 != m2
                Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 1024, alpha));
            }

        }
        public bool _ProvingAndVerifyingTest(BigInteger Exp, int keySize, int alpha)
        {
            // Sanity check
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void DifferentNTest()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_DifferentNTest(Exp, 2048, alpha));

        }
        public bool _DifferentNTest(BigInteger Exp, int keySize, int alpha)
        {
            // Modulus that is different than the one the verifier uses

            // The key pair used in Proving
            var keyPair = new RsaKey(Exp, keySize);
            // A different key pair to be used in verifying (assuming that we would less likely get the same P and Q twice).
            var diffKey = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;

            // The different public key to be used in verifying.
            var secPubKey = new RsaPubKey(diffKey);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);
            return PermutationTest.Verifying(secPubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void DifferentETest()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_DifferentETest(2048));
        }
        public bool _DifferentETest(int keySize)
        {
            // Different "e" than the verifier uses.

            // The key pair used in Proving
            var keyPair = new RsaKey(BigInteger.Three, keySize);
            var privKey = keyPair._privKey;

            // A different key pair to be used in verifying.
            var diffKey = new RsaKey(privKey.P, privKey.Q, new BigInteger("65537"));

            // The different public key to be used in verifying.
            var secPubKey = new RsaPubKey(diffKey);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);
            return PermutationTest.Verifying(secPubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void ShortN()
        {
            for (int i = 0; i < iterInValid; i++)
            {
                Assert.IsFalse(_ShortN(Exp, 1024, 2048));
                Assert.IsFalse(_ShortN(Exp, 500, 2048));
            }

        }
        public bool _ShortN(BigInteger Exp, int shortKeySize, int longKeySize)
        {
            // A case where "shortKeySize"-bits N is used for proving and "longKeySize"-bits is needed for verifying.
            var keyPair = new RsaKey(Exp, shortKeySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);
            // passing "longKeySize" as the keySize.
            return PermutationTest.Verifying(pubKey, signature, alpha, longKeySize, ps);
        }

        [TestMethod()]
        public void EvenE()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_EvenE(Exp, 2048));
        }
        public bool _EvenE(BigInteger Exp, int keySize)
        {
            /*
             * Let the RSA key be such that e=6.  Verification should fail.
             * This test generates an RSA key with e = Exp then passes (N, 6)
             * as the publicKey to the verifier function.
             * 
            */
            // Generating a "normal" RSA key
            var keyPair = new RsaKey(Exp, keySize);
            var privKey = keyPair._privKey;
            Exp = BigInteger.ValueOf(6);
            // Modifying the publicKey to be (N, 6) instead of (N, Exp).
            var pubKey = new RsaPubKey(privKey.Modulus, Exp);

            // Using the "normal" key to make signatures
            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, Exp, alpha, ps);
            // Passing the modified publicKey to verify.
            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void Test3A()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_Test3A(Exp, 2048));
        }
        public bool _Test3A(BigInteger Exp , int keySize)
        {
            /* Test 3A
             * Let p and q both be even numbers such that N is “sufficiently long”
             */

            BigInteger p, q;

            // Same construction as in BouncyCastle
            int pbitlength = (keySize + 1) / 2;
            int qbitlength = (keySize - pbitlength);

            for (;;)
            {
                p = TestUtils.GenRandomInt(pbitlength, false);
                q = TestUtils.GenRandomInt(qbitlength, false);
                BigInteger N = p.Multiply(q);
                if (!(N.BitLength == keySize))
                    break;
            }
            // This doesn't work for now because of the check in ModInverse for Q_inv
            var keyPair = new RsaKey(p, q, Exp);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

             return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void Test3B()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_Test3B(Exp, 2048));
        }
        public bool _Test3B(BigInteger Exp, int keySize)
        {
            /*
             * Test 3B
             * Let p be some non-even number that is not prime. q can be a normal good prime
             * such that N is “sufficiently long”.
            */

            BigInteger p, q;

            int pbitlength = (keySize + 1) / 2;
            int qbitlength = (keySize - pbitlength);

            p = TestUtils.GenRandomInt(pbitlength, true, false);
            q = TestUtils.GenQ(p, qbitlength, keySize, Exp);

            // This doesn't work for now because of the check in ModInverse for Q_inv
            var keyPair = new RsaKey(p, q, Exp);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void Test3C()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_Test3C(Exp, 2048));
        }
        public bool _Test3C(BigInteger Exp, int keySize)
        {
            /*
             * Test 3C
             * Let p=3 and q=some prime number such that N is “sufficiently long”
            */

            BigInteger p, q;

            p = BigInteger.Three;

            // Same construction as in BouncyCastle
            int pbitlength = p.BitLength;
            int qbitlength = (keySize - pbitlength);

            q = TestUtils.GenQ(p, qbitlength, keySize, Exp);

            var keyPair = new RsaKey(p, q, Exp);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void Test3D()
        {
            for (int i = 0; i < iterInValid; i++)
                Assert.IsFalse(_Test3D(Exp, 2048));
        }
        public bool _Test3D(BigInteger Exp, int keySize)
        {
            /*
             * Test 3D
             * Let p be the prime that comes immediately before alpha and q is some good prime
             * such that the modulus N=pq is still a "sufficiently long"
            */

            BigInteger p, q;

            // prime that comes immediately before alpha
            var primeN = Utils.Primes(alpha - 1).Last();

            p = BigInteger.ValueOf(primeN);

            // Same construction as in BouncyCastle
            int pbitlength = p.BitLength;
            int qbitlength = (keySize - pbitlength);

            q = TestUtils.GenQ(p, qbitlength, keySize, Exp);

            var keyPair = new RsaKey(p, q, Exp);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        [TestMethod()]
        public void Test3E()
        {
            for (int i = 0; i < iterValid; i++)
                Assert.IsTrue(_Test3E(Exp, 2048));
        }
        public bool _Test3E(BigInteger Exp, int keySize)
        {
            /*
             * Test 3E
             * Let p be alpha and q is some good prime such that
             * the modulus N=pq is still a "sufficiently long" 
             * 
            */

            BigInteger p, q;

            p = BigInteger.ValueOf(alpha);

            int pbitlength = p.BitLength;
            int qbitlength = (keySize - pbitlength);

            q = TestUtils.GenQ(p, qbitlength, keySize, Exp);

            var keyPair = new RsaKey(p, q, Exp);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }
    }

    [TestClass()]
    public class PoupardSternProtocolTests
    {
        // Change values here if needed.
        public int iterValid = 1; // Number of iterations for a valid test
        public int iterInValid = 1; // Number of iterations for an invalid test

        BigInteger Exp = BigInteger.Three;
        public byte[] ps = Strings.ToByteArray("public string");

        [TestMethod()]
        public void ProvingAndVerifyingTest()
        {
            for (int i = 0; i < iterValid; i++)
            {
                // (Exp, keySize, k)
                Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 4096, 128));
                Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 2048, 128));
                Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 1024, 128));
            }

        }
        public bool _ProvingAndVerifyingTest(BigInteger Exp, int keySize, int k)
        {
            // Sanity check
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);
            
            // Proving
            var outputTuple = PoupardStern.Proving(privKey.P, privKey.Q, privKey.PublicExponent, keySize, ps, k);

            var xValues = outputTuple.Item1;
            var y = outputTuple.Item2;
            
            // Verifying
            return PoupardStern.Verifying(pubKey, xValues, y, keySize, ps, k);
        }

        [TestMethod()]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ShortN()
        {
            for (int i = 0; i < iterInValid; i++)
            {
                Assert.IsFalse(_ShortN(Exp, 1024, 2048, 128));//returns False in verification.
                Assert.IsFalse(_ShortN(Exp, 500, 2048, 128)); //Throws an exception in proving()
            }

        }
        public bool _ShortN(BigInteger Exp, int shortKeySize, int longKeySize, int k)
        {
            // A case where "shortKeySize"-bits N is used for proving and "longKeySize"-bits is needed for verifying.
            var keyPair = new RsaKey(Exp, shortKeySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            // Proving
            var outputTuple = PoupardStern.Proving(privKey.P, privKey.Q, privKey.PublicExponent, shortKeySize, ps, k);

            var xValues = outputTuple.Item1;
            var y = outputTuple.Item2;

            // Verifying
            return PoupardStern.Verifying(pubKey, xValues, y, longKeySize, ps, k);
        }
    }


}
