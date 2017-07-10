using TumbleBit_Setup;
using System;
using TumbleBitSetup;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TumbleBit_Setup.Tests
{
    [TestClass()]
    public class ProtocolTests
    {
        [TestMethod()]
        public void genKeyTest()
        {
            Assert.Fail();
        }
    }
}

namespace TumbleBitSetup.Tests
{
    [TestClass]
    public class ProtocolTests
    {
        [TestMethod]
        public void CanProveAndVerify()
        {
            var alpha = 41;
            var key = genKey(new BigInteger("65537"));
            var privKey = (RsaPrivateCrtKeyParameters) key.Private;
            var pubKey = (RsaKeyParameters) key.Public;
            byte[][] signature = proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha);
            Assert.IsTrue(verifying(pubKey, signature, alpha));
        }
    }
}
