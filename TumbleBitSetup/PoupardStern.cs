using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;

namespace TumbleBitSetup
{
    public class PoupardStern
    {
        public static Tuple<BigInteger[], BigInteger> proving(BigInteger p, BigInteger q, BigInteger e, string ps = "public string", int k = 128)
        {
            int BigK;
            BigInteger r, w, y;

            // Generate a keyPair from p, q and e
            var keyPair = new RsaKey(p, q, e);

            var pubKey = new RsaPubKey(keyPair);
            var secKey = keyPair._privKey;

            BigInteger Modulus = pubKey._pubKey.Modulus;
            int ModulusBitLength = Modulus.BitLength;
            BigInteger upperLimit = BigInteger.Two.Pow(ModulusBitLength - 1);


            // Generate K (needs to be fixed)
            getK(k, Modulus, out BigK);

            // Initialize list of x values
            BigInteger[] xValues = new BigInteger[BigK];

            for (;;)
            {
                // Generate r
                getR(ModulusBitLength, out r);

                for (int i = 0; i < BigK; i++)
                {
                    // Generate z_i
                    BigInteger z_i = sampleFromZnStar(pubKey, ps, i, k, ModulusBitLength);
                    // Compute x_i
                    xValues[i] = z_i.ModPow(r, Modulus);
                }

                // Compute w
                getW(pubKey, ps, xValues, k, ModulusBitLength, out w);

                // Compute y
                BigInteger pSub1 = p.Subtract(BigInteger.One);
                BigInteger qSub1 = q.Subtract(BigInteger.One);
                BigInteger phi = pSub1.Multiply(qSub1);
                // Make sure the n == N in step 5, page 12
                y = r.Add(Modulus.Subtract(phi)).Multiply(w);

                // if y >= 2^{ |N| - 1 }
                if (y.CompareTo(upperLimit) >= 0)
                    continue;
                
                // if y < 0
                if (y.CompareTo(BigInteger.Zero) < 0)
                    continue;

                return new Tuple<BigInteger[], BigInteger>(xValues, y);

            }
            
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
        public static bool verifying(RsaPubKey pubKey, BigInteger[] xValues, BigInteger y, int keyLength, string ps = "public string", int k = 128)
        {
            int BigK;
            BigInteger w, rPrime;
            var Modulus = pubKey._pubKey.Modulus;
            var Exponent = pubKey._pubKey.Exponent;

            // Checking that:
            // if y >= 2^{ |N| - 1 }
            if (y.BitLength != keyLength) // Assuming that these two tests are equivalent.  
                return false;
            // if y < 0
            if (y.CompareTo(BigInteger.Zero) < 0)
                return false;
            // if N > 2^{KeySize-1}
            if (Modulus.BitLength != keyLength) // Step 2 wasn't clear if we should output INVALID for this case, but I assumed that we want N to be less that.
                return false;

            // Computing K
            getK(k, Modulus, out BigK);

            // Check if the number of x_values is not equal to K
            if (xValues.Length != BigK)
                return false;

            // Get w
            getW(pubKey, ps, xValues, k, keyLength, out w);

            // Computing rPrime
            rPrime = y.Subtract(Modulus.Multiply(w)); // Not clear if we should multiply N with W


            // Encrypting and verifying the signatures
            for (int i = 0; i < BigK; i++)
            {
                var z_i = sampleFromZnStar(pubKey, ps, i, k, keyLength);
                // Compute right side of the equality
                var rs = z_i.ModPow(rPrime, Modulus);
                // If the two sides are not equal
                if (xValues[i].CompareTo(rs) != 0)
                    return false;
            }
            return true;
        }

        internal static BigInteger sampleFromZnStar(RsaPubKey pubKey, string ps, int i, int k, int keyLength)
        {
            BigInteger Modulus = pubKey._pubKey.Modulus;
            int j = 2; // We might need to modify this
            // Octet Length of i
            int iLen = (int) Math.Ceiling( (1.0 / 8.0) * Math.Log( k + Math.Log( keyLength, 2.0), 2.0) );
            // Byte representation of i
            var EI = Utils.I2OSP(i, iLen);
            // ASN.1 encoding of the PublicKey
            var keyBytes = pubKey.ToBytes();
            // Byte representation of "public string"
            var psBytes = Strings.ToByteArray(ps);
            for (;;)
            {
                // OctetLength of j
                var jLen = Utils.getOctetLen(j);
                // Byte representation of j
                var EJ = Utils.I2OSP(j, jLen);
                // Combine PK with the rest of the string
                var combined = Utils.Combine(keyBytes, Utils.Combine(psBytes, Utils.Combine(EI, EJ)));
                // Pass the bytes to H_1
                byte[] ER = Utils.MGF1_SHA256(combined,keyLength);
                // Convert from Bytes to BigInteger
                BigInteger z_i = Utils.OS2IP(ER);
                // Check if the output is bigger or equal than N OR GCD(z_i, N) != 1
                if (z_i.CompareTo(Modulus) >= 0 || !z_i.Gcd(Modulus).Equals(BigInteger.One))
                {
                    j++;
                    continue;
                }
                return z_i;
            }
        }

        internal static void getW(RsaPubKey pubKey, string ps, BigInteger[] xValues, int k, int modulusBitLength, out BigInteger w)
        {
            // ASN.1 encoding of the PublicKey
            var keyBytes = pubKey.ToBytes();
            // Byte representation of "public string"
            var psBytes = Strings.ToByteArray(ps);
            // Encoding of the x_0
            var ExLen = (1 / 8) * modulusBitLength; // This assumes that |N| is 8 * x, should we add ceiling here?
            var Ex_0 = Utils.I2OSP(xValues[0], ExLen); // This assumes that we'll have at least one x Value, it could raise an "IndexOutOfRange" Error on empty list.
            // Encoding the rest of the x Values
            var BigK = xValues.Length;
            byte[] ExComb = Ex_0;
            for (int i = 1; i < BigK; i++)
            {
                var tmp = Utils.I2OSP(xValues[i], ExLen);
                ExComb = Utils.Combine(Ex_0, tmp);
                Ex_0 = ExComb;
            }
            // Concatenating the rest of s
            var s = Utils.Combine(keyBytes, Utils.Combine(psBytes, ExComb));
            // Hash the OctetString
            var BigW = Utils.SHA_256(s, k);
            // Convert to an Integer and return
            w = Utils.OS2IP(BigW);
        }

        /// <summary>
        /// Calculates the value of K as specified in the equation 6 in the setup
        /// </summary>
        /// <param name="k">Security parameter specified in the setup</param>
        /// <param name="N">RSA Modulus</param>
        internal static void getK(int k, BigInteger N, out int BigK)
        {
            double p1 = k + Math.Log(N.BitLength, 2.0);
            BigK = (int)Math.Ceiling(p1);
            return;
        }
        
        /// <summary>
        /// Calculates the value of r as specified in page 12 of the setup.
        /// </summary>
        /// <param name="BitLength">The length of the RSA Modulus</param>
        internal static void getR(int BitLength, out BigInteger r)
        {
            // !DOESN'T WORK FOR NOW!

            // Initialize a cryptographic randomness.
            SecureRandom random = new SecureRandom();
            // This is a huge numebr! Can't create a byte array that huge.
            // Doesn't work for now, need to think about it.
            BigInteger bitSize = BigInteger.Two.Pow(BitLength - 1);
            // Doesn't work for now.
            r = new BigInteger(System.Int32.MaxValue, random);
            return;
        }

    }

}