using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Diagnostics;
using System.Linq;

namespace TumbleBitSetup.Tests
{
    [TestClass()]
    public class Benchmark
    {
        public byte[] ps = Strings.ToByteArray("public string");
        public double iterations = 50.0;
        public int k = 128;
        public int[] alphaList = new int[13] { 41, 89, 191, 937, 1667, 3187, 3347, 7151, 8009, 19121, 26981, 65537, 319567 };
        public int[] keySizeList = new int[3] { 512, 1024, 2048 };
        public int[] kList = new int[3] { 80, 120, 128 };
        public BigInteger Exp = BigInteger.ValueOf(65537);
        public Stopwatch sw = new Stopwatch();

        [TestMethod()]
        public void BenchmarkPermutationTest()
        {
            Console.WriteLine($"Parameters,,, {keySizeList[0]}-bit RSA,, {keySizeList[1]}-bit RSA,, {keySizeList[2]}-bit RSA,");
            Console.WriteLine("alpha, m1, m2, Prove, Verify, Prove, Verify, Prove, Verify");

            foreach (int alpha in alphaList)
            {
                PermutationTest.Get_m1_m2(alpha, Exp.IntValue, k, out int m1, out int m2);
                Console.Write($"{alpha},{m1},{m2}");
                foreach (int keySize in keySizeList)
                {
                    double ProvingTime = 0.0;
                    double VerifyingTime = 0.0;
                    for (int i = 0; i < iterations; i++)
                    {
                        _ProvingAndVerifyingTest1(Exp, keySize, alpha, out double subPTime, out double subVTime);
                        ProvingTime += subPTime;
                        VerifyingTime += subVTime;
                    }
                    Console.Write($",{ProvingTime / iterations} ,{VerifyingTime / iterations}");
                }
                Console.WriteLine();
            }
        }

        [TestMethod()]
        public void BenchmarkPoupardStern()
        {
            keySizeList = new int[3] { 768, 1024, 2048 };
            Console.WriteLine("PoupardStern Protocol, keyLength, k, ProvingTime, VerifyingTime");


            foreach (int k in kList)
            {
                foreach (int keySize in keySizeList)
                {
                    double ProvingTime = 0.0;
                    double VerifyingTime = 0.0;
                    Console.Write(", {0}, {1}", keySize, k);
                    for (int i = 0; i < iterations; i++)
                    {
                        _ProvingAndVerifyingTest2(Exp, keySize, k, out double subPTime, out double subVTime);
                        Console.Write(", {0}, {1}", subPTime, subVTime);
                        ProvingTime += subPTime;
                        VerifyingTime += subVTime;
                    }
                    Console.WriteLine("");
                }
            }
        }

        [TestMethod()]
        public void BenchmarkCheckAlphaN()
        {
            Console.WriteLine("CheckAlphaN,, key Size,, ");
            Console.WriteLine($"alpha, {keySizeList[0]}, {keySizeList[1]}, {keySizeList[2]}");
            foreach (int alpha in alphaList)
            {
                Console.Write($"{alpha}");
                foreach (int keySize in keySizeList)
                {
                    double CheckTime = 0.0;
                    for (int i = 0; i < iterations; i++)
                    {
                        _CheckAlphaN(Exp, keySize, alpha, out double subCheckTime);
                        CheckTime += subCheckTime;
                    }
                    Console.Write($",{CheckTime / iterations}");
                }
                Console.WriteLine();
            }
        }

        [TestMethod()]
        public void BenchmarkPrimes()
        {
            Console.WriteLine("BenchmarkPrimes,,");
            Console.WriteLine($"alpha, running time ");
            foreach (int alpha in alphaList)
            {
                Console.Write($"{alpha}");
                double CheckTime = 0.0;
                for (int i = 0; i < iterations; i++)
                {
                    _Primes(alpha, out double subCheckTime);
                    CheckTime += subCheckTime;
                }
                Console.WriteLine($",{CheckTime / iterations}");
            }
        }

        [TestMethod()]
        public void BenchmarkKeyGen()
        {
            Console.WriteLine("Benchmark Key Generation,,");
            Console.WriteLine($"keysize, running time ");
            foreach (int key in keySizeList)
            {
                Console.Write(key);
                double CheckTime = 0.0;
                for (int i = 0; i < iterations; i++)
                {
                    _keyGen(key, out double subCheckTime);
                    CheckTime += subCheckTime;
                }
                Console.WriteLine($",{CheckTime / iterations}");
            }
        }

        [TestMethod()]
        public void PrimalityTest()
        {
            Console.WriteLine("Primality Test, keySize, Time");
            foreach (int keySize in keySizeList)
            {
                double CheckingTime = 0.0;
                for (int i = 0; i < iterations; i++)
                {
                    _PrimalityTest(keySize, 128, out double subCTime);
                    CheckingTime += subCTime;
                }
                Console.WriteLine($" ,{keySize} ,{CheckingTime / iterations}");
            }
        }

        public void _ProvingAndVerifyingTest1(BigInteger Exp, int keySize, int alpha, out double ProvingTime, out double VerifyingTime)
        {
            var setup = new PermutationTestSetup(ps, alpha, keySize);
            // PermutationTest Protocol
            var keyPair = TestUtils.GeneratePrivate(Exp, keySize);

            sw.Restart(); //Proving start
            var signature = ((RsaPrivateCrtKeyParameters)keyPair.Private).ProvePermutationTest(setup);
            sw.Stop();  //Proving ends
            
            ProvingTime = sw.Elapsed.TotalMilliseconds;

            sw.Restart(); //Verifying start
            var output = ((RsaKeyParameters)keyPair.Public).VerifyPermutationTest(signature, setup);
            sw.Stop();  //Verifying stops
          
            Assert.IsTrue(output);

        }

        public void _ProvingAndVerifyingTest2(BigInteger Exp, int keySize, int k, out double ProvingTime, out double VerifyingTime)
        {
            var setup = new PoupardSternSetup(ps, keySize, k);
            // PoupardStern Protocol
            var keyPair = TestUtils.GeneratePrivate(Exp, keySize);

            sw.Restart(); //Proving start
            var outputTuple = ((RsaPrivateCrtKeyParameters)keyPair.Private).ProvePoupardStern(setup);
            sw.Stop();  //Proving ends

            ProvingTime = sw.Elapsed.TotalSeconds;

            sw.Restart(); //Verifying start
            ((RsaKeyParameters)keyPair.Public).VerifyPoupardStern(outputTuple, setup);
            sw.Stop();  //Verifying stops

            VerifyingTime = sw.Elapsed.TotalSeconds;

        }

        public void _CheckAlphaN(BigInteger Exp, int keySize, int alpha, out double alphaTime)
        {
            var keyPair = TestUtils.GeneratePrivate(Exp, keySize);

            var pubKey = (RsaKeyParameters)keyPair.Public;
            var Modulus = pubKey.Modulus;

            sw.Restart(); //Check AlphaN start
            var output = PermutationTest.CheckAlphaN(alpha, Modulus);
            sw.Stop();  //Check AlphaN ends
            Assert.IsTrue(output);
            alphaTime = sw.Elapsed.TotalMilliseconds;
        }

        public void _Primes(int alpha, out double alphaTime)
        {
            sw.Restart(); //timer start
            var output = Utils.Primes(alpha-1).ToArray();
            sw.Stop();  //timer stops
            alphaTime = sw.Elapsed.TotalMilliseconds;
        }

        public void _keyGen(int keySize, out double Time)
        {
            sw.Restart(); //timer start
            var keyPair = TestUtils.GeneratePrivate(Exp, keySize);
            sw.Stop();  //timer stops
            Time = sw.Elapsed.TotalMilliseconds;
        }

        public void _TestReadingHexNum(string hexString, out double Time)
        {
            sw.Restart(); //Proving start
            var N = new BigInteger(hexString, 16);
            sw.Stop();  //Proving ends
            Time = sw.Elapsed.TotalMilliseconds;
        }
        
        public void _TestGcdBigInt(BigInteger Exp, int KeySize, BigInteger Primorial, out double Time)
        {
            var N = ((RsaKeyParameters)TestUtils.GeneratePrivate(Exp, KeySize).Public).Modulus;
            sw.Restart(); // start
            N.Gcd(Primorial);
            sw.Stop();  // end
            Time = sw.Elapsed.TotalMilliseconds;
        }

        public void _PrimalityTest(int keySize, int certainty, out double CheckingTime)
        {
            SecureRandom random = new SecureRandom();
            BigInteger p;
            for (;;)
            {
                p = new BigInteger(keySize, random);

                if (p.IsProbablePrime(certainty))
                    break;
            }

            sw.Restart();
            var isPrime = p.IsProbablePrime(certainty);
            sw.Stop();
            Assert.IsTrue(isPrime);
            CheckingTime = sw.Elapsed.TotalSeconds;
        }
    }
}
