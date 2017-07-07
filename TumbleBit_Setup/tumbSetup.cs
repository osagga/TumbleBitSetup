using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace TumbleBit_Setup
{
    public class TumbleBit_Setup
    {
        internal const int KeySize = 2048;
        internal static AlgorithmIdentifier algID = new AlgorithmIdentifier(
                    new DerObjectIdentifier("1.2.840.113549.1.1.1"), DerNull.Instance);

        public static void proving(BigInteger p, BigInteger q, BigInteger e, int alpha, out byte[][] sigs, string pks = "public string", int k = 120)
        {
            int m1, m2;
            byte[][] rhoValues;

            // Generate m1 and m2
            get_m1_m2((decimal)alpha, e.IntValue, k, out m1, out m2);

            // Generate private and public keys
            BigInteger N = p.Multiply(q);
            var eN = N.Multiply(e);

            // Generate a pair (pub, priv) of keys for e and eN
            var keyPair = GeneratePrivate(p, q, e);
            var keyPrimePair = GeneratePrivate(p, q, eN);

            // Extract keys from the pairs
            var pubKey = (RsaKeyParameters)keyPair.Public;
            var privKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            var privKeyPrime = (RsaPrivateCrtKeyParameters)keyPrimePair.Private;

            // Generate list of rho values
            getRhos(m2, pks, pubKey, out rhoValues);

            // Signing the Rho values
            sigs = new byte[m2][];
            for (int i = 0; i < m2; i++)
            {
                if (i <= m1)
                    sigs[i] = Decrypt(privKeyPrime, rhoValues[i]);
                else
                    sigs[i] = Decrypt(privKey, rhoValues[i]);
            }
            return;
        }

        public static bool verifying(RsaKeyParameters pubKey, byte[][] sigs, int alpha, string pks = "public string", int k = 120)
        {
            var Modulus = pubKey.Modulus;
            byte[][] rhoValues;

            // Checking N
            if (!(Modulus.CompareTo(new BigInteger("2").Pow(KeySize - 1)) >= 0))
                return false;

            // Generate m1 and m2
            int m1, m2;
            get_m1_m2((decimal)alpha, pubKey.Exponent.IntValue, k, out m1, out m2);

            // Verifying m2
            if (!m2.Equals(sigs.Length))
                return false;

            // Verify alpha and N
            if (!checkAlphaN(alpha, Modulus))
                return false;

            // Generate a "weird" public key
            var eN = Modulus.Multiply(pubKey.Exponent);
            var pubKeyPrime = new RsaKeyParameters(false, Modulus, eN);

            // Generate list of rho values
            getRhos(m2, pks, pubKey, out rhoValues);

            // Encrypting and verifying the signatures
            for (int i = 0; i < m2; i++)
            {
                if (i <= m1)
                {
                    var dec_sig = Encrypt(pubKeyPrime, sigs[i]);
                    if (!dec_sig.SequenceEqual(rhoValues[i]))
                        return false;
                }
                else
                {
                    var dec_sig = Encrypt(pubKey, sigs[i]);
                    if (!dec_sig.SequenceEqual(rhoValues[i]))
                        return false;
                }
            }
            return true;
        }

        public static bool checkAlphaN(int alpha, BigInteger N)
        {
            int[] primesList = Primes(alpha - 1).ToArray();
            int primeCount = primesList.Length;

            for (int i = 0; i < primeCount; i++)
            {
                if (!N.Gcd(BigInteger.ValueOf(primesList[i])).Equals(BigInteger.One))
                    return false;
            }
            return true;
        }
        public static IEnumerable<int> Primes(int bound)
        {
            // From here https://codereview.stackexchange.com/questions/56480/getting-all-primes-between-0-n

            if (bound < 2) yield break;
            //The first prime number is 2
            yield return 2;

            BitArray composite = new BitArray((bound - 1) / 2);
            int limit = ((int)(Math.Sqrt(bound)) - 1) / 2;
            for (int i = 0; i < limit; i++)
            {
                if (composite[i]) continue;
                //The first number not crossed out is prime
                int prime = 2 * i + 3;
                yield return prime;
                //cross out all multiples of this prime, starting at the prime squared
                for (int j = (prime * prime - 2) >> 1; j < composite.Count; j += prime)
                {
                    composite[j] = true;
                }
            }
            //The remaining numbers not crossed out are also prime
            for (int i = limit; i < composite.Count; i++)
            {
                if (!composite[i]) yield return 2 * i + 3;
            }
        }
        public static byte[] hashFuc(byte[] data)
        {
            byte[] output = new byte[256];
            Sha256Digest sha256 = new Sha256Digest();
            var generator = new Mgf1BytesGenerator(sha256);
            generator.Init(new MgfParameters(data));
            generator.GenerateBytes(output, 0, output.Length);
            return output;
        }

        public static void get_m1_m2(decimal alpha, int e, int k, out int m1, out int m2)
        {
            double p1 = -(k + 1) / Math.Log(1.0 / ((double)alpha), 2.0);
            double p22 = 1.0 / ((double)alpha) + (1.0 / ((double)e)) * (1.0 - (1.0 / ((double)alpha)));
            double p2 = -(k + 1) / Math.Log(p22, 2.0);
            m1 = (int)Math.Ceiling(p1);
            m2 = (int)Math.Ceiling(p2);
            return;
        }

        public static void getRhos(int m2, string pks, RsaKeyParameters pubKey, out byte[][] rhoValues)
        {
            rhoValues = new byte[m2][];
            BigInteger Modulus = pubKey.Modulus;
            for (int i = 0; i < m2; i++)
            {
                int j = 0;
                while (true)
                {
                    string s_key = Encoding.ASCII.GetString(pubKeyToBytes(pubKey));
                    string s = s_key + pks + i.ToString() + j.ToString();
                    byte[] sBytes = Encoding.UTF8.GetBytes(s);
                    byte[] output = hashFuc(sBytes);
                    BigInteger input = new BigInteger(1, output);
                    if (input.CompareTo(Modulus) >= 0)
                    {
                        j++;
                        continue;
                    }
                    rhoValues[i] = output;
                    break;
                }
            }
        }

        public static byte[] Decrypt(RsaPrivateCrtKeyParameters privKey, byte[] encrypted)
        {
            if (encrypted == null)
                throw new ArgumentNullException(nameof(encrypted));

            RsaEngine engine = new RsaEngine();
            engine.Init(false, privKey);

            return engine.ProcessBlock(encrypted, 0, encrypted.Length);
        }

        public static byte[] Encrypt(RsaKeyParameters pubKey, byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            RsaEngine engine = new RsaEngine();
            engine.Init(true, pubKey);

            return engine.ProcessBlock(data, 0, data.Length);
        }

        public static AsymmetricCipherKeyPair genKey(BigInteger Exp, int keySize = KeySize)
        {
            SecureRandom random = new SecureRandom();
            var gen = new RsaKeyPairGenerator();
            gen.Init(new RsaKeyGenerationParameters(Exp, random, KeySize, 2)); // See A.15.2 IEEE P1363 v2 D1 for certainty parameter
            var pair = gen.GenerateKeyPair();
            return pair;
        }

        public static AsymmetricCipherKeyPair GeneratePrivate(BigInteger p, BigInteger q, BigInteger e)
        {
            BigInteger n, d, pSub1, qSub1, phi;

            n = p.Multiply(q);

            pSub1 = p.Subtract(BigInteger.One);
            qSub1 = q.Subtract(BigInteger.One);
            phi = pSub1.Multiply(qSub1);

            //
            // calculate the private exponent
            //

            d = e.ModInverse(phi);

            //
            // calculate the CRT factors
            //
            BigInteger dP, dQ, qInv;

            dP = d.Remainder(pSub1);
            dQ = d.Remainder(qSub1);
            qInv = q.ModInverse(p);

            return new AsymmetricCipherKeyPair(
                new RsaKeyParameters(false, n, e),
                new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));

        }

        public static byte[] pubKeyToBytes(RsaKeyParameters pubKey)
        {
            RsaPublicKeyStructure keyStruct = new RsaPublicKeyStructure(
                pubKey.Modulus,
                pubKey.Exponent);
            var privInfo = new PrivateKeyInfo(algID, keyStruct.ToAsn1Object());
            return privInfo.ToAsn1Object().GetEncoded();
        }

        public static bool TestRealKey()
        {
            var alpha = 4999;
            var key = genKey(new BigInteger("65537"));
            var trickKey = genKey(BigInteger.Three);
            var trickPubKey = (RsaKeyParameters)trickKey.Public;
            var privKey = (RsaPrivateCrtKeyParameters)key.Private;
            var pubKey = (RsaKeyParameters)key.Public;
            byte[][] signature;
            proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, out signature);
            return verifying(pubKey, signature, alpha);
        }

        public static bool TestFakeKey()
        {
            var alpha = 4999;
            var key = GeneratePrivate(new BigInteger("13"), new BigInteger("20"), BigInteger.Three);
            var privKey = (RsaPrivateCrtKeyParameters)key.Private;
            var pubKey = (RsaKeyParameters)key.Public;
            byte[][] signature;
            proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, out signature);
            return verifying(pubKey, signature, alpha);
        }

        public static void TestPrimes(int bound)
        {
            Console.WriteLine(string.Join(" ", Primes(bound).ToArray()));
        }

        static void Main(string[] args)
        {
            Console.WriteLine(TestRealKey());
            // TestPrimes(7);
            // Console.WriteLine(TestFakeKey());
            Console.WriteLine("-----Done----- Press Any Key To Exit.");
            Console.ReadLine();
        }

    }

}