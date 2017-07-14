using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using System;
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
        internal static byte[] MGF1_SHA256(byte[] data, int keySize)
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
        /// Returns how many Octets are needed to represent the integer x
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        internal static int getOctetLen(int x)
        {
            return (int)Math.Ceiling((1.0 / 8.0) * Math.Log(x, 2));
        }
        
        /// <summary>
        /// Generates a list of primes up to and including the input bound
        /// </summary>
        /// <param name="bound"> Bound to generate primes up to</param>
        /// <returns> Iterator over the list of primes</returns>
        internal static IEnumerable<int> Primes(int bound)
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
        /// converts a non-negative integer to an octet string of a specified length.
        /// </summary>
        /// <param name="x">non-negative integer</param>
        /// <param name="xLen">specified length</param>
        /// <returns></returns> 
        internal static byte[] I2OSP(int x, int xLen)
        {
            byte[] outBytes = new byte[xLen];

            if (x < 0)
                throw new ArgumentOutOfRangeException("only positive integers");

            // checks If x >= 256^xLen
            if (BigInteger.ValueOf(x).CompareTo(BigInteger.ValueOf(256).Pow(xLen)) >= 0)
                throw new ArithmeticException("integer too large");

            // converts x to an unsigned byteArray.
            for (int i = 0; (x > 0) && (i < outBytes.Length); i++)
            {
                outBytes[i] = (byte)(x % 256);
                x /= 256;
            }
            
            // make sure the output is BigEndian
            if (BitConverter.IsLittleEndian)
                Array.Reverse(outBytes, 0, outBytes.Length);

            return outBytes;
        }

        /// <summary>
        /// converts an octet string to a nonnegative BigInteger.
        /// </summary>
        /// <param name="x">Octet String</param>
        /// <returns></returns>
        public static BigInteger OS2IP(byte[] x)
        {
            int i;

            // To skip the first leading zeros (if they exist)
            for (i = 0; (x[i] == 0x00) && (i < x.Length); i++)
                continue;
            i--;

            if (i > 0)
            {
                // If there exits leading zeros, skip them
                byte[] result = new byte[x.Length - i];
                Buffer.BlockCopy(x, i, result, 0, result.Length);
                return new BigInteger(1, result);
            }
            else
                return new BigInteger(1, x);
        }
    }
}
