using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using System;
using System.Linq;
using System.Collections.Generic;


namespace TumbleBitSetup.Tests
{
    class TestUtils
    {
        /// <summary>
        /// Generates a random BigInteger with the given length
        /// </summary>
        /// <param name="bitSize"> Size of the output number</param>
        /// <param name="isOdd">If the required number is Odd</param>
        /// <returns></returns>
        public static BigInteger GenRandomInt(int bitSize, bool isOdd, bool isPrime = false)
        {
            if (!isOdd && isPrime)
                throw new ArithmeticException("Can't have a number that's both prime and even");

            SecureRandom random = new SecureRandom();
            BigInteger p;
            for (;;)
            {
                p = new BigInteger(bitSize, random);

                // Same certainty parameter as TumbleBit
                if (!(p.IsProbablePrime(2) == isPrime))
                    continue;

                if (p.Mod(BigInteger.ValueOf(2)).Equals(BigInteger.ValueOf(Convert.ToInt32(isOdd))))
                    break;
            }
            return p;
        }

        /// <summary>
        /// Generate Q according to the RSA standards (assuming BouncyCastle applies the standards)
        /// </summary>
        /// <param name="p"> The P value of the RSA key</param>
        /// <param name="qbitlength"> The required bit size of Q</param>
        /// <param name="strength"> The RSA key size</param>
        /// <param name="e"> The RSA public exponent</param>
        /// <returns></returns>
        public static BigInteger GenQ(BigInteger p, int qbitlength, int strength, BigInteger e)
        {
            SecureRandom random = new SecureRandom();
            // From BouncyCastle
            int mindiffbits = strength / 3;
            // From TumbleBit, See A.15.2 IEEE P1363 v2 D1 for certainty parameter
            int certainty = 2;
            BigInteger q, n;
            for (;;)
            {
                // Generate q, prime and (q-1) relatively prime to e,
                // and not equal to p
                //
                for (;;)
                {
                    q = new BigInteger(qbitlength, 1, random);

                    if (q.Subtract(p).Abs().BitLength < mindiffbits)
                        continue;

                    if (q.Mod(e).Equals(BigInteger.One))
                        continue;

                    if (!q.IsProbablePrime(certainty))
                        continue;

                    if (e.Gcd(q.Subtract(BigInteger.One)).Equals(BigInteger.One))
                        break;
                }

                //
                // calculate the modulus
                // This also checks if N >= 2^{keySize - 1}
                //
                n = p.Multiply(q);

                if (n.BitLength == strength)
                    break;

                //
                // if we Get here our primes aren't big enough, try again
                //
            }

            return q;

        }

        /// <summary>
        /// Checks if t1 is a subset of t2
        /// </summary>
        /// <param name="t1"></param>
        /// <param name="t2"></param>
        /// <returns>true if t2 is a subset of t1, false otherwise</returns>
        public static bool isSubset(List<int> t1, List<int> t2)
        {
            // From here https://stackoverflow.com/questions/332973/check-whether-an-array-is-a-subset-of-another
            return !t1.Except(t2).Any();
        }

        /// <summary>
        /// Converts a hex string to a ByteArray
        /// </summary>
        /// <param name="hex">The input hex string.</param>
        /// <returns></returns>
        public static byte[] StringToByteArray(string hex)
        {
            // https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

    }
}
