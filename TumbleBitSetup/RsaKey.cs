using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using System;

namespace TumbleBitSetup
{
    public class RsaKey
    {
        internal readonly RsaPrivateCrtKeyParameters _privKey;
        internal readonly RsaKeyParameters _pubKey;

        /// <summary>
        /// Generates a new RSA key pair (public and private)
        /// </summary>
        /// <param name="Exp">Public exponent to use for generation</param>
        /// <param name="keySize">The size of the key to generate</param>
        /// <returns>RSA key pair (public and private)</returns>
        public RsaKey(BigInteger Exp, int keySize)
        {
            SecureRandom random = new SecureRandom();
            var gen = new RsaKeyPairGenerator();
            gen.Init(new RsaKeyGenerationParameters(Exp, random, keySize, 2)); // See A.15.2 IEEE P1363 v2 D1 for certainty parameter
            var pair = gen.GenerateKeyPair();
            _privKey = (RsaPrivateCrtKeyParameters)pair.Private;
            _pubKey = (RsaKeyParameters)pair.Public;
        }

        /// <summary>
        /// Generates a new RSA key pair (public and private) given P, Q and e
        /// </summary>
        /// <param name="p">P</param>
        /// <param name="q">Q</param>
        /// <param name="e">Public Exponent</param>
        /// <returns>RSA key pair</returns>
        public RsaKey(BigInteger p, BigInteger q, BigInteger e)
        {
            var pair = GeneratePrivate(p, q, e);
            _privKey = (RsaPrivateCrtKeyParameters)pair.Private;
            _pubKey = (RsaKeyParameters)pair.Public;
        }

        public RsaKey(AsymmetricCipherKeyPair keyPair)
        {
            _privKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
            _pubKey = (RsaKeyParameters)keyPair.Public;
        }

        RsaPubKey _PublicKey;
        public RsaPubKey PublicKey
        {
            get
            {
                if (_PublicKey == null)
                    _PublicKey = new RsaPubKey(_pubKey);
                return _PublicKey;
            }
        }

        /// <summary>
        /// Preforms RSA decryption (or signing) using private key.
        /// </summary>
        /// <param name="encrypted">Data to decrypt (or sign)</param>
        /// <returns></returns>
        internal byte[] Decrypt(byte[] encrypted)
        {
            if (encrypted == null)
                throw new ArgumentNullException(nameof(encrypted));

            RsaEngine engine = new RsaEngine();
            engine.Init(false, _privKey);

            return engine.ProcessBlock(encrypted, 0, encrypted.Length);
        }

        public PoupardSternProof CreatePoupardSternProof(PoupardSternSetup setup)
        {
            var proof = PoupardStern.Proving(_privKey.P, _privKey.Q, _privKey.PublicExponent, _privKey.Modulus.BitLength, setup.PublicString, setup.SecurityParameter);
            return new PoupardSternProof(proof);
        }

        public PermutationTestProof CreatePermutationTestProof(PermutationTestSetup setup)
        {
            var proof = PermutationTest.Proving(_privKey.P, _privKey.Q, _privKey.PublicExponent, setup.Alpha, setup.PublicString, setup.SecurityParameter);
            return new PermutationTestProof(proof);
        }

        /// <summary>
        /// Generates a private key given P, Q and e
        /// </summary>
        /// <param name="p">P</param>
        /// <param name="q">Q</param>
        /// <param name="e">Public Exponent</param>
        /// <returns>RSA key pair</returns>
        internal static AsymmetricCipherKeyPair GeneratePrivate(BigInteger p, BigInteger q, BigInteger e)
        {
            BigInteger n = p.Multiply(q);

            BigInteger One = BigInteger.One;
            BigInteger pSub1 = p.Subtract(One);
            BigInteger qSub1 = q.Subtract(One);
            BigInteger gcd = pSub1.Gcd(qSub1);
            BigInteger lcm = pSub1.Divide(gcd).Multiply(qSub1);

            //
            // calculate the private exponent
            //
            BigInteger d = e.ModInverse(lcm);

            if (d.BitLength <= q.BitLength)
                throw new ArgumentException("Invalid RSA q value");

            //
            // calculate the CRT factors
            //
            BigInteger dP = d.Remainder(pSub1);
            BigInteger dQ = d.Remainder(qSub1);
            BigInteger qInv = q.ModInverse(p);

            return new AsymmetricCipherKeyPair(
                new RsaKeyParameters(false, n, e),
                new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
        }

        internal byte[] ToBytes()
        {
            RsaPrivateKeyStructure keyStruct = new RsaPrivateKeyStructure(
                _privKey.Modulus,
                _privKey.PublicExponent,
                _privKey.Exponent,
                _privKey.P,
                _privKey.Q,
                _privKey.DP,
                _privKey.DQ,
                _privKey.QInv);

            var privInfo = new PrivateKeyInfo(algID, keyStruct.ToAsn1Object());
            return privInfo.ToAsn1Object().GetEncoded();
        }

        internal static AlgorithmIdentifier algID = new AlgorithmIdentifier(
                    new DerObjectIdentifier("1.2.840.113549.1.1.1"), DerNull.Instance);
    }
}
