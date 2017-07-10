using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using System.Collections.Generic;
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TumbleBitSetup.Tests
{
    [TestClass()]
    public class ProtocolTests
    {
        [TestMethod()]
        public void provingAndVerifyingTest()
        {
            var alpha = 41;
            var keyPair = new RsaKey(new BigInteger("65537"));

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsTrue(TumbleBitSetup.verifying(pubKey, signature, alpha));
        }

        [TestMethod()]
        public void CanGeneratePrimes()
        {
            var bound = 101;
            IEnumerable<int> primesList = Utils.Primes(bound);
            string s = "";
            foreach (int p in primesList)
                s += p.ToString() + " ";

            Console.WriteLine(s);
        }

        //[TestMethod()]
        public void FakeKeyTest()
        {
            // Doesn't work at the moment because of "d = e.ModInverse(phi);" when generating a private key.
            var alpha = 41;
            var keyPair = new RsaKey(new BigInteger("13"), new BigInteger("20"), BigInteger.Three);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsTrue(TumbleBitSetup.verifying(pubKey, signature, alpha));
        }


    }
}
