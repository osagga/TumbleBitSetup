using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
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
            var keyPair = TumbleBitSetup.genKey(new BigInteger("65537"));

            var privKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
            var pubKey = (RsaKeyParameters)keyPair.Public;

            byte[][] signature = TumbleBitSetup.proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);

            Assert.IsTrue(TumbleBitSetup.verifying(pubKey, signature, alpha));
        }

    }
}
