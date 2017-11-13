using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.Linq;

namespace TumbleBitSetup.Tests
{
    //[TestClass()]
    public class Runner
    {
        public static void testKey(int Exp, double iterations, double subIterations)
        {
            // Generate a list of 'iterations' keys.
            var keys = genRandKeys((int)iterations, BigInteger.ValueOf(Exp));
            // Generate a list of 'iterations' inputs.
            byte[][] data = genRandData(keys);

            // Normal RSA
            double EncTime = 0.0;
            double DecTime = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                // Test key 'i' with input 'i' 'subIterations' times.
                testData(keys[i], data[i], subIterations, out double SubEncTime, out double SubDecTime);
                EncTime += SubEncTime;
                DecTime += SubDecTime;
            }
            Console.WriteLine($"Normal RSA   |Encryption |e = {Exp}| {EncTime / iterations} ms");
            Console.WriteLine($"Normal RSA   |Decryption |e = {Exp}| {DecTime / iterations} ms");

            // Weird RSA

            for (int i = 0; i < iterations; i++)
            {
                // Extract the private key 'i' from the keypair 'i'
                var key = ((RsaPrivateCrtKeyParameters)keys[i].Private);
                BigInteger N = key.Modulus;
                // Generate a new private key with e = e * N
                keys[i] = GeneratePrivate(key.P, key.Q, N.Multiply(key.PublicExponent));
            }

            EncTime = 0.0;
            DecTime = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                // Test key 'i' with input 'i' 'subIterations' times.
                testData(keys[i], data[i], subIterations, out double SubEncTime, out double SubDecTime);
                EncTime += SubEncTime;
                DecTime += SubDecTime;
            }

            Console.WriteLine($"Weird RSA    |Encryption |e = {Exp}| {EncTime / iterations} ms");
            Console.WriteLine($"Weird RSA    |Decryption |e = {Exp}| {DecTime / iterations} ms");

            return;
        }

        public static void testData(AsymmetricCipherKeyPair key, byte[] input, double iterations, out double EncTime, out double DecTime)
        {
            Stopwatch sw = new Stopwatch();

            // Encrypt
            byte[] cipherText = ((RsaKeyParameters)key.Public).Encrypt(input);
            // Decrypt
            byte[] plainText = ((RsaPrivateCrtKeyParameters)key.Private).Decrypt(cipherText);
            // Validate
            if (!plainText.SequenceEqual(input))
                throw new InvalidCipherTextException("Validation Failed");

            // Benchmarks

            // Encryption
            sw.Restart();

            for (int i = 0; i < iterations; i++)
                ((RsaKeyParameters)key.Public).Encrypt(input);

            sw.Stop();

            EncTime = sw.Elapsed.TotalMilliseconds / iterations;

            // Decryption
            sw.Restart();

            for (int i = 0; i < iterations; i++)
                ((RsaPrivateCrtKeyParameters)key.Private).Decrypt(cipherText);

            sw.Stop();

            DecTime = sw.Elapsed.TotalMilliseconds / iterations;

            return;
        }

        public static AsymmetricCipherKeyPair[] genRandKeys(int count, BigInteger e)
        {
            AsymmetricCipherKeyPair[] keys = new AsymmetricCipherKeyPair[count];

            for (int i = 0; i < count; i++)
                keys[i] = genKey(e);

            return keys;
        }

        public static byte[] GenEncryptableData(RsaKeyParameters _key)
        {
            var Modulus = _key.Modulus;
            var KeySize = _key.Modulus.BitLength;
            SecureRandom random = new SecureRandom();

            while (true)
            {
                byte[] bytes = new byte[KeySize / 8];
                random.NextBytes(bytes);
                BigInteger input = new BigInteger(1, bytes);

                if (input.CompareTo(Modulus) >= 0)
                    continue;

                return bytes;
            }
        }

        public static byte[][] genRandData(AsymmetricCipherKeyPair[] keys)
        {
            var count = keys.Length;
            var data = new byte[count][];

            for (int i = 0; i < count; i++)
                data[i] = GenEncryptableData((RsaKeyParameters)keys[i].Public);

            return data;
        }

        public static AsymmetricCipherKeyPair genKey(BigInteger Exp, int KeySize = 2048)
        {
            SecureRandom random = new SecureRandom();
            var gen = new RsaKeyPairGenerator();
            gen.Init(new RsaKeyGenerationParameters(Exp, random, KeySize, 100));
            var pair = gen.GenerateKeyPair();
            return pair;
        }

        public static AsymmetricCipherKeyPair GeneratePrivate(BigInteger p, BigInteger q, BigInteger e)
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

        [TestMethod()]
        public void BenchmarkRSAops()
        {
            // Number of (key, input) pairs
            double iterations = 10.0;
            // Number of iterations per pair
            double subIterations = 100.0;

            // Test e = 3
            testKey(3, iterations, subIterations);

            // Test e = 65537
            testKey(65537, iterations, subIterations);
        }

    }
}
