using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1;
using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TumbleBitSetup.Tests
{

    [TestClass()]
    public class ProtocolTests
    {
        // Change values here if needed.
        public int alpha = 41;
        public int keySize = 2048;
        public BigInteger Exp = BigInteger.Three;

        [TestMethod()]
        public void provingAndVerifyingTest()
        {
            // Sanity check
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsTrue(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void DiffrentNTest()
        {
            // Modulus that is different than the one the verifier uses

            // The key pair used in Proving
            var keyPair = new RsaKey(Exp, keySize);
            // A different key pair to be used in verifying (assuming that we would less likely get the same P and Q twice).
            var diffKey = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;

            // The different public key to be used in verifying.
            var secPubKey = new RsaPubKey(diffKey);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);
            Assert.IsFalse(TumbleBitSetup.verifying(secPubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void DiffrentETest()
        {
            // Different "e" than the verifier uses.

            // The key pair used in Proving
            var keyPair = new RsaKey(BigInteger.Three, keySize);
            var privKey = keyPair._privKey;

            // A different key pair to be used in verifying.
            var diffKey = new RsaKey(privKey.P, privKey.Q, new BigInteger("65537"));

            // The different public key to be used in verifying.
            var secPubKey = new RsaPubKey(diffKey);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);
            Assert.IsFalse(TumbleBitSetup.verifying(secPubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void shortKeySize()
        {
            // A case where keySize is 1024-bits long (Sanity check)
            var keySize = 1024;
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);
            Assert.IsTrue(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void test_I2OSP_l()
        {
            // Test if we can encode and decode successfully.
            int size = 10;

            for (int i = 100; i < 10000; i++)
            {
                byte[] encoded = Utils.I2OSP(i, size);
                BigInteger decoded = Utils.OS2IP(encoded);

                Assert.AreEqual(decoded, BigInteger.ValueOf(i));
            }

        }

        [TestMethod()]
        [ExpectedException(typeof(ArithmeticException))]
        public void test_I2OSP_2()
        {
            // Test if size is smaller than needed.
            // Should give a ArithmeticException.
            int x = 99999999;
            int size = 1;
            Utils.I2OSP(x, size);
        }

        [TestMethod()]
        public void Test3E_multiple()
        {
            /*
             * Repeat test 3E a 100 times with a different modulus N each time.
             * (This assumes that TestUtils.GenQ() will give a new q every time)
            */
            for (int i = 0; i < 100; i++)
                Test3E();
        }

        [TestMethod()]
        public void shortN()
        {
            // A case where N is a 1024 - bit long prime(rather than 2048 - bits)
            var keySize = 1024;
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);
            // The keySize that was passed is 2048
            Assert.IsFalse(TumbleBitSetup.verifying(pubKey, signature, alpha, 2048));
        }

        [TestMethod()]
        public void evenE()
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
            // Modifing the publicKey to be (N, 6) instead of (N, Exp).
            var pubKey = new RsaPubKey(privKey.Modulus, BigInteger.ValueOf(6));

            // Using the "normal" key to make signatures
            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);
            // Passing the modified publicKey to verify.
            Assert.IsFalse(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void prefixPrimes()
        {
            // confirm that the output of TestUtils.Prime(A) is the prefix of the output of TestUtils.Prime(B), where B >> A
            for (int i = 100; i < 200; i++)
            {
                var smallPrimeList = Utils.Primes(i).ToList();
                var largePrimeList = Utils.Primes(i+1).ToList();
                Assert.IsTrue(TestUtils.isSubset(smallPrimeList, largePrimeList));
            }
        }

        [TestMethod()]
        public void Test3A()
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

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsFalse(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void Test3B()
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

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsFalse(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void Test3C()
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

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsFalse(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void Test3D()
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

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsFalse(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

        [TestMethod()]
        public void Test3E()
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

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsTrue(TumbleBitSetup.verifying(pubKey, signature, alpha, keySize));
        }

    }
}
