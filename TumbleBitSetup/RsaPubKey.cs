using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Engines;
using System;

namespace TumbleBitSetup
{
    public class RsaPubKey
    {
        internal readonly RsaKeyParameters _pubKey;

        public RsaPubKey(RsaKeyParameters key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _pubKey = key;
        }

        public RsaPubKey(RsaKey key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _pubKey = key._pubKey;
        }

        public RsaPubKey(BigInteger N, BigInteger e)
        {
            _pubKey = new RsaKeyParameters(false, N, e);
        }

        public bool VerifyPoupardSternProof(PoupardSternProof proof, PoupardSternSetup setup)
        {
            return PoupardStern.Verifying(this, proof.XValues, proof.YValue, setup.KeySize, setup.PublicString, setup.SecurityParameter);
        }

        public bool VerifyPermutationTestProof(PermutationTestProof proof, PermutationTestSetup setup)
        {
            return PermutationTest.Verifying(this, proof.Signatures, setup.Alpha, setup.KeySize, setup.PublicString, setup.SecurityParameter);
        }

        /// <summary>
        /// Preforms RSA encryption using public key.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns></returns>
        internal byte[] Encrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            RsaEngine engine = new RsaEngine();
            engine.Init(true, _pubKey);

            return engine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Converts a public key to ByteArray using the standard Asn1 standards for the specified PKCS-1.
        /// </summary>
        /// <returns>ByteArray representing the public key</returns>
        internal byte[] ToBytes()
        {
            RsaPublicKeyStructure keyStruct = new RsaPublicKeyStructure(
                _pubKey.Modulus,
                _pubKey.Exponent);
            var privInfo = new PrivateKeyInfo(RsaKey.algID, keyStruct.ToAsn1Object());
            return privInfo.ToAsn1Object().GetEncoded();
        }
    }
}
