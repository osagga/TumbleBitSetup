using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

namespace TumbleBitSetup
{
    public class Utils
    {
        /// <summary>
        /// MGF1 Mask Generation Function based on the SHA-256 hash function
        /// </summary>
        /// <param name="data">Input to process</param>
        /// <param name="keySize">The size of the RSA key in bits</param>
        /// <returns>Hashed result as a 256 Bytes array (2048 Bits)</returns>
        internal static byte[] hashFuc(byte[] data, int keySize)
        {
            byte[] output = new byte[keySize/8];
            Sha256Digest sha256 = new Sha256Digest();
            var generator = new Mgf1BytesGenerator(sha256);
            generator.Init(new MgfParameters(data));
            generator.GenerateBytes(output, 0, output.Length);
            return output;
        }
        
        /// <summary>
        /// Combines two ByteArrays
        /// </summary>
        /// <param name="arr1">First array</param>
        /// <param name="arr2">Second array</param>
        /// <returns>The resultant combined list</returns>
        internal static byte[] Combine(byte[] arr1, byte[] arr2)
        {
            var len = arr1.Length + arr2.Length;
            var combined = new byte[len];

            System.Buffer.BlockCopy(arr1, 0, combined, 0, arr1.Length);
            System.Buffer.BlockCopy(arr2, 0, combined, arr1.Length, arr2.Length);

            return combined;
        }

        /// <summary>
        /// Generates a list of primes up to and including the input bound
        /// </summary>
        /// <param name="bound"> Bound to generate primes up to</param>
        /// <returns> Iterator over the list of primes</returns>
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
        /// Checks if t2 is a subset of t1
        /// </summary>
        /// <param name="t1"></param>
        /// <param name="t2"></param>
        /// <returns>true if t2 is a subset of t1, false otherwise</returns>
        public static bool isSubset(List<int> t1,List<int> t2)
        {
            // From here https://stackoverflow.com/questions/332973/check-whether-an-array-is-a-subset-of-another
            return !t1.Except(t2).Any();
        }
    }
}
