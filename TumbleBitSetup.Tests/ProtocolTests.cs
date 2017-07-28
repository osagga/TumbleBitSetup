using Org.BouncyCastle.Math;
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
            // Doesn't work yet, check with #15
            var data1 = Strings.ToByteArray("TEST42");
            var data2 = Strings.ToByteArray("TEST222");
            var keySize = 856; // Not really sure why the length of mask1 is 107 bytes
            var keySizeBytes = Utils.GetByteLength(keySize);
            var seed1 = TestUtils.StringToByteArray("d6e168c5f256a2dcff7ef12facd390f393c7a88d");
            var mask1 = "0742ba966813af75536bb6149cc44fc256fd6406df79665bc31dc5"
                      + "a62f70535e52c53015b9d37d412ff3c1193439599e1b628774c50d9c"
                      + "cb78d82c425e4521ee47b8c36a4bcffe8b8112a89312fc04420a39de"
                      + "99223890e74ce10378bc515a212b97b8a6447ba6a8870278";

            var output1 = Utils.MGF1_SHA256(data1, keySize);
            var output11 = Utils.MGF1_SHA256(data1, keySize);
            var output2 = Utils.MGF1_SHA256(data2, keySize);
            var output3 = Utils.MGF1_SHA256(seed1, keySize);

            var expectedOutput3 = TestUtils.StringToByteArray(mask1);

            // Test that the length is correct
            Assert.AreEqual(output1.Length, keySizeBytes);
            // Test that the same input gives the same output
            Assert.IsTrue(output11.SequenceEqual(output1));
            // Test that the two output are different
            Assert.IsFalse(output1.SequenceEqual(output2));
            // Assert that seed1 Test holds
            Assert.IsTrue(output3.SequenceEqual(expectedOutput3));
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
            int x = 255; // this is 0xff, so it should give 1
            int y = 256; // this is 0x100, so it should give 2
            int z = 1;
            int k = 5;

            var xLen = Utils.GetOctetLen(x);
            var yLen = Utils.GetOctetLen(y);
            var zLen = Utils.GetOctetLen(z);
            var kLen = Utils.GetOctetLen(k);

            Assert.IsTrue(xLen.Equals(1));
            Assert.IsTrue(yLen.Equals(2));
            Assert.IsTrue(zLen.Equals(1));
            Assert.IsTrue(kLen.Equals(1));
        }

        [TestMethod()]
        public void SHA256_Test()
        {
            var data1 = Strings.ToByteArray("TEST42");
            var data2 = Strings.ToByteArray("TEST22");
            byte[] TEST6 = new byte[1] { (byte)0x19 };

            var output1 = Utils.SHA256(data1);
            var output11 = Utils.SHA256(data1);
            var output2 = Utils.SHA256(data2);
            var output3 = Utils.SHA256(TEST6);

            // Convert output to String
            var output3String = BitConverter.ToString(output3).Replace("-", "");

            // Test that the length is correct
            Assert.AreEqual(output1.Length, 32);
            // Test that the same input gives the same output
            Assert.IsTrue(output11.SequenceEqual(output1));
            // Test that the two output are different
            Assert.IsFalse(output1.SequenceEqual(output2));
            // Test TEST6 from https://tools.ietf.org/html/rfc6234#section-8.5 (top of page 98)
            Assert.IsTrue(output3String.Equals("68AA2E2EE5DFF96E3355E6C7EE373E3D6A4E17F75F9518D843709C0C9BC3E3D4"));
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
        int keySize = 2048;
        BigInteger Exp = BigInteger.Three;
        public byte[] ps = Strings.ToByteArray("public string");

        // unit tests for sub-functions
        [TestMethod()]
        public void GetRhosTest()
        {
            // GetRhos is really producing outputs rho that are<N and have GCD(N, rho) = 1
            int m2 = 11;
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            var Modulus = pubKey._pubKey.Modulus;

            // Generate list of rho values
            PermutationTest.GetRhos(m2, ps, pubKey, keySize, out byte[][] rhoValues);

            for (int i = 0; i < rhoValues.Length; i++)
            {
                // Convert rho value to a number
                var num = Utils.OS2IP(rhoValues[i]);
                // Assert it's less than N
                //Assert.IsTrue(num.CompareTo(Modulus) < 0);
                Assert.IsTrue(Modulus.Subtract(num).LongValue > 0);
                // Assert GCD(rho, N) == 1
                Assert.IsTrue(Modulus.Gcd(num).Equals(BigInteger.One));
            }
        }

        [TestMethod()]
        public void CheckAlphaNTest1()
        {
            // CheckAlphaN outputs fail if N has some prime number p < alpha as a factor.
            BigInteger p, q;

            // prime that comes immediately before alpha
            var primeN = Utils.Primes(alpha - 1).Last();

            p = BigInteger.ValueOf(primeN);

            int pbitlength = p.BitLength;
            int qbitlength = (keySize - pbitlength);

            // Generate q
            q = TestUtils.GenQ(p, qbitlength, keySize, Exp);

            var Modulus = p.Multiply(q);
            
            // Assert CheckAlphaN returns False
            Assert.IsFalse(PermutationTest.CheckAlphaN(alpha, Modulus));
        }

        [TestMethod()]
        public void CheckAlphaNTest2()
        {
            // CheckAlphaN outputs fail if N is even.
            // Sanity check
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            var Modulus = pubKey._pubKey.Modulus;

            var ModBytes = Modulus.ToByteArray();
            // Make the LSB a zero to make it even.
            ModBytes[ModBytes.Length - 1] &= (byte)0xfe;

            Modulus = new BigInteger(1, ModBytes);

            // Assert CheckAlphaN returns False
            Assert.IsFalse(PermutationTest.CheckAlphaN(alpha, Modulus));
        }

        [TestMethod()]
        public void CheckAlphaNTest3()
        {
            // CheckAlphaN outputs fail if N is even (2 * alpha).
            BigInteger p, q;

            // p is Two (Even)
            p = BigInteger.Two;

            // Generate q to fill N
            q = BigInteger.ValueOf(alpha);

            var Modulus = p.Multiply(q);

            // Assert CheckAlphaN returns False
            Assert.IsFalse(PermutationTest.CheckAlphaN(alpha, Modulus));
        }

        [TestMethod()]
        public void Get_m1_m2Test()
        {
            // Get_m1_m2 produce outputs that match those in Section 2.7 of setup.pdf
            var k = 128;
            var Exp = 65537;
            PermutationTest.Get_m1_m2(41, Exp, k, out int m1, out int m2);
            Assert.IsTrue(m1.Equals(25) && m2.Equals(25));
            PermutationTest.Get_m1_m2(997, Exp, k, out m1, out m2);
            Assert.IsTrue(m1.Equals(13) && m2.Equals(13));
            PermutationTest.Get_m1_m2(4999, Exp, k, out m1, out m2);
            Assert.IsTrue(m1.Equals(11) && m2.Equals(11));
            PermutationTest.Get_m1_m2(7649, Exp, k, out m1, out m2);
            Assert.IsTrue(m1.Equals(10) && m2.Equals(11));
            PermutationTest.Get_m1_m2(20663, Exp, k, out m1, out m2);
            Assert.IsTrue(m1.Equals(9) && m2.Equals(10));
            PermutationTest.Get_m1_m2(33469, Exp, k, out m1, out m2);
            Assert.IsTrue(m1.Equals(9) && m2.Equals(9));
        }

        // unit tests for main functions

        [TestMethod()]
        public void ProvingAndVerifyingTest()
        {
            // repeating the test "iterValid" times
            var alphaList = new int[6] { 41, 997, 4999, 7649, 20663, 33469 };
            var keySizeList = new int[3] { 1024, 2048, 4096 };
            var kList = new int[3] { 128, 80, 120 };

            foreach (int alpha in alphaList)
                foreach (int keySize in keySizeList)
                    foreach (int k in kList)
                        for (int i = 0; i < iterValid; i++)
                            Assert.IsTrue(_ProvingAndVerifyingTest(Exp, keySize, alpha, k));

            Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 1001, alpha, 128)); // weird length key case
            Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 245, alpha, 128)); // weird length key case
            Assert.IsTrue(_ProvingAndVerifyingTest(new BigInteger("65537"), 2048, 7649, alpha)); // Case where m1 != m2
        }
        public bool _ProvingAndVerifyingTest(BigInteger Exp, int keySize, int alpha, int k)
        {
            // Sanity check
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps, k);

            return PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps, k);
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
             * such that the modulus N=PxQ is still a "sufficiently long"
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
        int keySize = 2048;
        public byte[] ps = Strings.ToByteArray("public string");

        // unit tests for sub functions

        [TestMethod()]
        public void SampleFromZnStarTest()
        {
            // SampleFromZnStar is really producing z_i that are <N
            int BigK = 129; // If k = 128
            keySize = 2048;

            var keyPair = new RsaKey(Exp, keySize);
            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            var Modulus = pubKey._pubKey.Modulus;

            for (int i = 0; i < BigK; i++)
            {
                var num = PoupardStern.SampleFromZnStar(pubKey, ps, i, BigK, keySize);
                // Assert that num is < N
                //Assert.IsTrue(num.CompareTo(Modulus) < 0);
                Assert.IsTrue(Modulus.Subtract(num).LongValue > 0);
            }
        }

        [TestMethod()]
        public void GetWTest()
        {
            var k = 128;
            var BigK = k+1;
            var keyPair = new RsaKey(Exp, keySize);
            var pubKey = new RsaPubKey(keyPair);

            var Modulus = pubKey._pubKey.Modulus;

            // Initialize list of z values
            BigInteger[] zValues = new BigInteger[BigK];

            // Generate the list of z Values
            for (int i = 0; i < BigK; i++)
                zValues[i] = PoupardStern.SampleFromZnStar(pubKey, ps, i, BigK, keySize);

            // Initialize list of x values.
            BigInteger[] xValues = new BigInteger[BigK];

            // Generate r
            PoupardStern.GetR(keySize, out BigInteger r);

            for (int j = 0; j < BigK; j++)
                // Compute x_i
                xValues[j] = zValues[j].ModPow(r, Modulus);

            // Compute w
            PoupardStern.GetW(pubKey, ps, xValues, k, keySize, out BigInteger w);

            // Check that the bitLength of w equals to k.
            Assert.IsTrue(w.BitLength.Equals(k));
        }
        
        // unit tests for main functions

        [TestMethod()]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ProvingAndVerifyingTest()
        {
            var kList = new int[3] { 128, 80, 120 };
            var keySizeList = new int[3] { 1024, 2048, 4096 };

            foreach (int k in kList)
                foreach(int keySize in keySizeList)
                    for (int i = 0; i < iterValid; i++)
                        // (Exp, keySize, k)
                        Assert.IsTrue(_ProvingAndVerifyingTest(Exp, keySize, k));

            Assert.IsTrue(_ProvingAndVerifyingTest(Exp, 1001, 128)); // weird length keySize
            Assert.IsFalse(_ProvingAndVerifyingTest(Exp, 245, 128)); // throws an exception

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
