using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Diagnostics;
using System;
using System.Linq;
using System.Collections.Generic;

namespace TumbleBitSetup
{

    // TODO: edit the page number references in the comments or remove them.
    public class PermutationTest
    {
        public static Stopwatch sw = new Stopwatch();
        
        /// <summary>
        /// Proving Algorithm specified in (2.8.1) of the setup
        /// </summary>
        /// <param name="p">P in the secret key</param>
        /// <param name="q">Q in the secret key</param>
        /// <param name="e">Public Exponent in the public key</param>
        /// <param name="alpha">Prime number specified in the setup</param>
        /// <param name="psBytes">The public string from the setup</param>
        /// <param name="k">Security parameter as specified in the setup.</param>
        /// <returns>List of signatures</returns>
        public static byte[][] Proving(BigInteger p, BigInteger q, BigInteger e, int alpha, byte[] psBytes, int k = 128)
        {
            byte[][] sigs;

            // Generate m1 and m2
            Get_m1_m2((decimal)alpha, e.IntValue, k, out int m1, out int m2);

            // Generate private and public keys
            BigInteger N = p.Multiply(q);
            BigInteger eN = N.Multiply(e);

            // Generate a pair (pub, sec) of keys for e and eN
            var keyPair = new RsaKey(p, q, e);
            var keyPrimePair = new RsaKey(p, q, eN);

            // Extract public key (N, e) from main key.
            var pubKey = new RsaPubKey(keyPair);

            // Generate list of rho values
            GetRhos(m2, psBytes, pubKey, N.BitLength, out byte[][] rhoValues);

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

        public static byte[][] BenchProving(BigInteger p, BigInteger q, BigInteger e, int alpha, byte[] psBytes, out double time1, out double time2, int k = 128)
        {
            // Benching generating values
            sw.Restart();

            byte[][] sigs;

            // Generate m1 and m2
            Get_m1_m2((decimal)alpha, e.IntValue, k, out int m1, out int m2);

            // Generate private and public keys
            BigInteger N = p.Multiply(q);
            BigInteger eN = N.Multiply(e);

            // Generate a pair (pub, sec) of keys for e and eN
            var keyPair = new RsaKey(p, q, e);
            var keyPrimePair = new RsaKey(p, q, eN);

            // Extract public key (N, e) from main key.
            var pubKey = new RsaPubKey(keyPair);

            // Generate list of rho values
            GetRhos(m2, psBytes, pubKey, N.BitLength, out byte[][] rhoValues);

            sw.Stop();
            time1 = sw.Elapsed.Milliseconds;

            // Benching the verification process
            sw.Restart();
            // Signing the Rho values
            sigs = new byte[m2][];
            for (int i = 0; i < m2; i++)
            {
                if (i <= m1)
                    sigs[i] = keyPrimePair.Decrypt(rhoValues[i]);
                else
                    sigs[i] = keyPair.Decrypt(rhoValues[i]);
            }
            sw.Stop();
            time2 = sw.Elapsed.TotalMilliseconds;
            return sigs;
        }

        public static void BenchVerifying(RsaPubKey pubKey, byte[][] sigs, int alpha, int keyLength, byte[] psBytes, out double time1, out double time2, out double time3, out double time33, out double time4, int k = 128)
        {
            // Benching setup
            sw.Restart();
            BigInteger Two = BigInteger.Two;
            var Modulus = pubKey._pubKey.Modulus;
            var Exponent = pubKey._pubKey.Exponent;
            sw.Stop();
            time1 = sw.Elapsed.TotalMilliseconds;

            // Benching calculating limits
            sw.Restart();
            BigInteger lowerLimit = Two.Pow(keyLength - 1);
            BigInteger upperLimit = Two.Pow(keyLength);
            sw.Stop();
            time2 = sw.Elapsed.TotalMilliseconds;

            // Benching checks
            sw.Restart();
            // if N < 2^{KeySize-1}
            if (Modulus.CompareTo(lowerLimit) < 0)
                ;
            // if N >= 2^{KeySize}
            if (Modulus.CompareTo(upperLimit) >= 0)
                ;
            sw.Stop();
            time3 = sw.Elapsed.TotalMilliseconds;
            
            // Benching generating values
            sw.Restart();
            // Generate m1 and m2
            Get_m1_m2((decimal)alpha, Exponent.IntValue, k, out int m1, out int m2);

            // Verifying m2
            if (!m2.Equals(sigs.Length))
                ;

            // Verify alpha and N
            if (!CheckAlphaN(alpha, Modulus))
                ;

            // Generate a "weird" public key
            var eN = Modulus.Multiply(Exponent);
            var pubKeyPrime = new RsaPubKey(new RsaKeyParameters(false, Modulus, eN));

            // Generate list of rho values
            GetRhos(m2, psBytes, pubKey, keyLength, out byte[][] rhoValues);
            sw.Stop();
            time33 = sw.Elapsed.Milliseconds;
            // Benching the verification process
            sw.Restart();
            // Verifying the signatures
            for (int i = 0; i < m2; i++)
            {
                if (i <= m1)
                {
                    var dec_sig = pubKeyPrime.Encrypt(sigs[i]);
                    if (!dec_sig.SequenceEqual(rhoValues[i]))
                        ;
                }
                else
                {
                    var dec_sig = pubKey.Encrypt(sigs[i]);
                    if (!dec_sig.SequenceEqual(rhoValues[i]))
                        ;
                }
            }
            sw.Stop();
            time4 = sw.Elapsed.TotalMilliseconds;
        }

        /// <summary>
        /// Verifying Algorithm specified in (2.8.2) of the setup
        /// </summary>
        /// <param name="pubKey">Public Key used to verify the signatures</param>
        /// <param name="sigs">List of signatures to verify</param>
        /// <param name="alpha">Prime number specified in the setup</param>
        /// <param name="keyLength">The size of the RSA key in bits</param>
        /// <param name="psBytes">The public string from the setup</param>
        /// <param name="k">Security parameter as specified in the setup.</param>
        /// <returns> true if the signatures verify, false otherwise</returns>
        public static bool Verifying(RsaPubKey pubKey, byte[][] sigs, int alpha, int keyLength, byte[] psBytes, int k = 128)
        {

            BigInteger Two = BigInteger.Two;
            var Modulus = pubKey._pubKey.Modulus;
            var Exponent = pubKey._pubKey.Exponent;

            BigInteger lowerLimit = Two.Pow(keyLength - 1);
            BigInteger upperLimit = Two.Pow(keyLength);

            // if N < 2^{KeySize-1}
            if (Modulus.CompareTo(lowerLimit) < 0)
                return false;

            // if N >= 2^{KeySize}
            if (Modulus.CompareTo(upperLimit) >= 0)
                return false;

            // Generate m1 and m2
            Get_m1_m2((decimal)alpha, Exponent.IntValue, k, out int m1, out int m2);

            // Verifying m2
            if (!m2.Equals(sigs.Length))
                return false;

            // Verify alpha and N
            if (!CheckAlphaN(alpha, Modulus))
                return false;

            // Generate a "weird" public key
            var eN = Modulus.Multiply(Exponent);
            var pubKeyPrime = new RsaPubKey(new RsaKeyParameters(false, Modulus, eN));

            // Generate list of rho values
            GetRhos(m2, psBytes, pubKey, keyLength, out byte[][] rhoValues);

            // Verifying the signatures
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
        /// <param name="N"> Modulus used in the public key</param>
        /// <returns>true if the check passes, false otherwise</returns>
        internal static bool CheckAlphaN(int alpha, BigInteger N)
        {
            IEnumerable<int> primesList = Utils.Primes(alpha - 1);

            foreach (int p in primesList)
            {
                if (!(N.Gcd(BigInteger.ValueOf(p)).Equals(BigInteger.One)))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Generates the values m1 and m2 as specified in the "proving" protocol in section 2.8
        /// </summary>
        /// <param name="alpha">Prime number specified in the setup</param>
        /// <param name="e">Public Exponent used in the public key</param>
        /// <param name="k">Security parameter specified in the setup</param>
        internal static void Get_m1_m2(decimal alpha, int e, int k, out int m1, out int m2)
        {
            double p1 = -(k + 1) / Math.Log(1.0 / ((double)alpha), 2.0);
            double p22 = 1.0 / ((double)alpha) + (1.0 / ((double)e)) * (1.0 - (1.0 / ((double)alpha)));
            double p2 = -(k + 1) / Math.Log(p22, 2.0);
            m1 = (int)Math.Ceiling(p1);
            m2 = (int)Math.Ceiling(p2);
            return;
        }

        /// <summary>
        /// Generates a list of rho values as specified in the setup (2.8.1)
        /// </summary>
        /// <param name="m2">m2</param>
        /// <param name="psBytes">public string specified in the setup</param>
        /// <param name="key">Public key used</param>
        /// <param name="keyLength">The size of the RSA key in bits</param>
        internal static void GetRhos(int m2, byte[] psBytes, RsaPubKey key, int keyLength, out byte[][] rhoValues)
        {
            var m2Len = Utils.GetOctetLen(m2);
            rhoValues = new byte[m2][];
            BigInteger Modulus = key._pubKey.Modulus;

            // ASN.1 encoding of the PublicKey
            var keyBytes = key.ToBytes();

            for (int i = 0; i < m2; i++)
            {
                // Byte representation of i
                var EI = Utils.I2OSP(i, m2Len);
                int j = 2;
                // Combine the octet string
                var combined = Utils.Combine(keyBytes, Utils.Combine(psBytes, EI));
                while (true)
                {
                    // OctetLength of j
                    var jLen = Utils.GetOctetLen(j);
                    // Byte representation of j
                    var EJ = Utils.I2OSP(j, jLen);
                    // Combine EJ with the rest of the string
                    var sub_combined = Utils.Combine(combined, EJ);
                    // Pass the bytes to H_1
                    byte[] ER = Utils.MGF1_SHA256(sub_combined, keyLength);
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