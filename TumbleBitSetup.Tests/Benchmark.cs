using Org.BouncyCastle.Math;
using System;
using System.Diagnostics;
using Org.BouncyCastle.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;

namespace TumbleBitSetup.Tests
{
    [TestClass()]
    public class Benchmark
    {
        public byte[] ps = Strings.ToByteArray("public string");
        public double iterations = 100.0;
        public BigInteger Exp = BigInteger.ValueOf(65537);
        public Stopwatch sw = new Stopwatch();

        [TestMethod()]
        public void BenchmarkPermutationTest()
        {
            //var alphaList = new int[6] { 41, 997, 4999, 7649, 20663, 33469 };
            //var keySizeList = new int[3] { 512, 1024, 2048};
            var alphaList = new int[12] { 43, 991, 1723, 1777, 3391, 3581, 7649, 8663, 20663, 30137, 71471, 352831 }; //Spredsheet values
            var keySizeList = new int[1] { 2048 }; //Spredsheet values
            Console.WriteLine("PermutationTest Protocol, alpha, keyLength, ProvingTime, VerifyingTime");

            foreach (int alpha in alphaList)
            {
                foreach (int keySize in keySizeList)
                {
                    double ProvingTime = 0.0;
                    double VerifyingTime = 0.0;
                    for (int i = 0; i < iterations; i++)
                    {
                        // Fixing k at 128
                        _ProvingAndVerifyingTest1(Exp, keySize, alpha, 128, out double subPTime, out double subVTime);
                        ProvingTime += subPTime;
                        VerifyingTime += subVTime;
                    }
                    Console.WriteLine(" ,{0} ,{1} ,{2} ,{3}", alpha, keySize, ProvingTime / iterations, VerifyingTime / iterations);
                }
            }
        }
        [TestMethod()]
        public void BenchmarkPoupardStern()
        {
            var kList = new int[3] { 128, 80, 120 };
            var keySizeList = new int[3] { 768, 1024, 2048 };
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
            //var alphaList = new int[6] { 41, 997, 4999, 7649, 20663, 33469 };
            //var keySizeList = new int[3] {512, 1024, 2048};

            var alphaList = new int[12] { 43, 991, 1723, 1777, 3391, 3581, 7649, 8663, 20663, 30137, 71471, 352831 }; //Spredsheet values
            var keySizeList = new int[1] { 2048 }; //Spredsheet values

            Console.WriteLine("checkAlphaN , alpha, keyLength, Check Time");

            foreach (int alpha in alphaList)
            {
                foreach (int keySize in keySizeList)
                {
                    double CheckTime = 0.0;
                    for (int i = 0; i < iterations; i++)
                    {
                        _CheckAlphaN(Exp, keySize, alpha, out double subCheckTime);
                        CheckTime += subCheckTime;
                    }
                    Console.WriteLine(" ,{0} ,{1} ,{2}", alpha, keySize, CheckTime / iterations);
                }
            }
        }

        public void _ProvingAndVerifyingTest1(BigInteger Exp, int keySize, int alpha, int k, out double ProvingTime, out double VerifyingTime)
        {
            var setup = new PermutationTestSetup(ps, alpha, k);
            // PermutationTest Protocol
            var keyPair = TestUtils.GeneratePrivate(Exp, keySize);

            sw.Restart(); //Proving start
            var signature = ((RsaPrivateCrtKeyParameters)keyPair.Private).ProvePermutationTest(setup);
            sw.Stop();  //Proving ends

            ProvingTime = sw.Elapsed.TotalSeconds;

            sw.Restart(); //Verifying start
            ((RsaKeyParameters)keyPair.Public).VerifyPermutationTest(signature, setup);
            sw.Stop();  //Verifying stops

            VerifyingTime = sw.Elapsed.TotalSeconds;
        }
        public void _ProvingAndVerifyingTest2(BigInteger Exp, int keySize, int k, out double ProvingTime, out double VerifyingTime)
        {
            var setup = new PoupardSternSetup(ps, k);
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

            var privKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
            var pubKey = (RsaKeyParameters)keyPair.Public;

            var Modulus = pubKey.Modulus;

            sw.Restart(); //Check AlphaN start
            PermutationTest.CheckAlphaN(alpha, Modulus);
            sw.Stop();  //Check AlphaN ends

            alphaTime = sw.Elapsed.TotalSeconds;
        }

    }
}
