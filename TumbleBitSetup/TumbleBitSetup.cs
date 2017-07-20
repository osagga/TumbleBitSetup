using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Linq;
using System.Collections.Generic;

namespace TumbleBitSetup
{
    public class TumbleBitSetup
    {
        /// <summary>
        /// Generate a list of signatures as specified in "Proving" at Sec 2.8
        /// </summary>
        /// <param name="p">P in the secret key</param>
        /// <param name="q">Q in the secret key</param>
        /// <param name="e">Public Exponent in the public key</param>
        /// <param name="alpha">Prime number specified in the setup</param>
        /// <param name="k">Security parameter as specified in the setup.</param>
        /// <param name="pks">The "public string" from the setup</param>
        /// <returns>The resulting signatures</returns>
        public static byte[][] proving(BigInteger p, BigInteger q, BigInteger e, int alpha, string pks = "public string", int k = 128)
        {
            int m1, m2;
            byte[][] rhoValues, sigs;

            // Generate m1 and m2
            get_m1_m2((decimal)alpha, e.IntValue, k, out m1, out m2);

            // Generate private and public keys
            BigInteger N = p.Multiply(q);
            var eN = N.Multiply(e);

            // Generate a pair (pub, priv) of keys for e and eN
            var keyPair = new RsaKey(p, q, e);
            var keyPrimePair = new RsaKey(p, q, eN);

            // Extract public key (N, e) from main key.
            var pubKey = new RsaPubKey(keyPair);

            // Generate list of rho values
            getRhos(m2, pks, pubKey, N.BitLength, out rhoValues);

            // Signing the Rho values
            sigs = new byte[m2][];
            for (int i = 0; i < m2; i++)
            {
                if (i <= m1)
                    sigs[i] = keyPrimePair.Decrypt(rhoValues[i]);
                else
                    sigs[i] = keyPair.Decrypt(rhoValues[i]);
            }
            return sigs;
        }

        /// <summary>
        /// Verifies a list of signatures as specified in "Verifying" at Sec 2.8
        /// </summary>
        /// <param name="pubKey">Public Key used to verify the signatures</param>
        /// <param name="sigs">List of signatures to verify</param>
        /// <param name="alpha">Prime number specified in the setup</param>
        /// <param name="keySize">The size of the RSA key in bits</param>
        /// <param name="k">Security parameter as specified in the setup.</param>
        /// <param name="pks">The "public string" from the setup</param>
        /// <returns> true if the signatures verify, false otherwise</returns>
        public static bool verifying(RsaPubKey pubKey, byte[][] sigs, int alpha, int keySize, string pks = "public string", int k = 128)
        {
            var Modulus = pubKey._pubKey.Modulus;
            var Exponent = pubKey._pubKey.Exponent;
            byte[][] rhoValues;

            // Checking that N > 2^{KeySize-1}
            if (!(Modulus.BitLength == keySize))
                return false;

            // Generate m1 and m2
            int m1, m2;
            get_m1_m2((decimal)alpha, Exponent.IntValue, k, out m1, out m2);

            // Verifying m2
            if (!m2.Equals(sigs.Length))
                return false;

            // Verify alpha and N
            if (!checkAlphaN(alpha, Modulus))
                return false;

            // Generate a "weird" public key
            var eN = Modulus.Multiply(Exponent);
            var pubKeyPrime = new RsaPubKey(new RsaKeyParameters(false, Modulus, eN));

            // Generate list of rho values
            getRhos(m2, pks, pubKey, keySize, out rhoValues);

            // Encrypting and verifying the signatures
            for (int i = 0; i < m2; i++)
            {
                if (i <= m1)
                {
                    var dec_sig = pubKeyPrime.Encrypt(sigs[i]);
                    if (!dec_sig.SequenceEqual(rhoValues[i]))
                        return false;
                }
                else
                {
                    var dec_sig = pubKey.Encrypt(sigs[i]);
                    if (!dec_sig.SequenceEqual(rhoValues[i]))
                        return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Provides the check specified in step 3 of the verifying protocol.
        /// </summary>
        /// <param name="alpha"> Prime number specified in the setup</param>
        /// <param name="N"> Modulus used in the public key used to sign the values</param>
        /// <returns>true if the check passes, false otherwise</returns>
        internal static bool checkAlphaN(int alpha, BigInteger N)
        {
            IEnumerable<int> primesList = Utils.Primes(alpha - 1);

            foreach (int p in primesList)
            {
                if (!N.Gcd(BigInteger.ValueOf(p)).Equals(BigInteger.One))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Generates the values m1 and m2 as specified in the "proving" protocol in section 2.8
        /// </summary>
        /// <param name="alpha">Prime number specified in the setup</param>
        /// <param name="e">Public Exponent used in the public key used to sign the rho values</param>
        /// <param name="k">Security parameter specified in the setup</param>
        /// <param name="m1">Variable to store m1 in</param>
        /// <param name="m2">Variable to store m2 in</param>
        internal static void get_m1_m2(decimal alpha, int e, int k, out int m1, out int m2)
        {
            double p1 = -(k + 1) / Math.Log(1.0 / ((double)alpha), 2.0);
            double p22 = 1.0 / ((double)alpha) + (1.0 / ((double)e)) * (1.0 - (1.0 / ((double)alpha)));
            double p2 = -(k + 1) / Math.Log(p22, 2.0);
            m1 = (int)Math.Ceiling(p1);
            m2 = (int)Math.Ceiling(p2);
            return;
        }

        /// <summary>
        /// Generates a list of rho values as specified in the while-loop in the setup (section 2.8)
        /// </summary>
        /// <param name="m2">m2 as calculated</param>
        /// <param name="pks">"public string" specified in the setup</param>
        /// <param name="key">Public key used</param>
        /// <param name="keySize">The size of the RSA key in bits</param>
        /// <param name="rhoValues">List of the resulting rho values</param>
        internal static void getRhos(int m2, string pks, RsaPubKey key, int keySize, out byte[][] rhoValues)
        {
            var m2Len = Utils.getOctetLen(m2);
            rhoValues = new byte[m2][];
            BigInteger Modulus = key._pubKey.Modulus;

            // ASN.1 encoding of the PublicKey
            var keyBytes = key.ToBytes();
            // Byte representation of "public string"
            var psBytes = Strings.ToByteArray(pks);

            for (int i = 0; i < m2; i++)
            {
                // Byte representation of i
                var EI = Utils.I2OSP(i, m2Len);
                int j = 2;
                while (true)
                {
                    // OctetLength of j
                    var jLen = Utils.getOctetLen(j);
                    // Byte representation of j
                    var EJ = Utils.I2OSP(j, jLen);
                    // Combine PK with the rest of the string
                    var combined = Utils.Combine(keyBytes, Utils.Combine(psBytes,Utils.Combine(EI, EJ)));
                    // Pass the bytes to H_1
                    byte[] ER = Utils.MGF1_SHA256(combined, keySize);
                    // Convert from Bytes to BigInteger
                    BigInteger input = Utils.OS2IP(ER);
                    // Check if the output is bigger or equal than N
                    if (input.CompareTo(Modulus) >= 0)
                    {
                        j++;
                        continue;
                    }
                    rhoValues[i] = ER;
                    break;
                }
            }
        }
    }

}