using Org.BouncyCastle.Math;
using System;
using System.Diagnostics;
using Org.BouncyCastle.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TumbleBitSetup.Tests
{
    [TestClass()]
    public class Benchmark
    {
        public byte[] ps = Strings.ToByteArray("public string");
        public double iterations = 50.0;
        public BigInteger Exp = BigInteger.ValueOf(65537);
        public Stopwatch sw = new Stopwatch();

        [TestMethod()]
        public void microBenchmarkPermutationTest1()
        {
            // For the proving function
            var alphaList = new int[1] { 30137 }; //microBenchmark value
            var keySizeList = new int[1] { 2048 };
            Console.WriteLine("Proving function, alpha, keySize");
            foreach (int alpha in alphaList)
            {
                foreach (int keySize in keySizeList)
                {
                    double time1 = 0.0; // Benching generating values
                    double time2 = 0.0; // Benching the proving process
                    for (int i = 0; i < iterations; i++)
                    {
                        _ProvingAndVerifyingTest12(Exp, keySize, alpha, 128, out double subTime1, out double subTime2);
                        time1 += subTime1;
                        time2 += subTime2;
                    }

                    Console.WriteLine(" ,{0} ,{1} ,Benching generating values: {2} ,Benching the proving process: {3}", alpha, keySize, time1 / iterations, time2 / iterations);
                }
            }
        }

        [TestMethod()]
        public void microBenchmarkPermutationTest()
        {
            // For the verifying function
            var alphaList = new int[1] { 30137 }; //microBenchmark value
            var keySizeList = new int[1] { 2048 };
            Console.WriteLine("Verifying function, alpha, keySize");

            foreach (int alpha in alphaList)
            {
                foreach (int keySize in keySizeList)
                {
                    double time1 = 0.0; // Benching setup
                    double time2 = 0.0; // Benching calculating limits
                    double time3 = 0.0; // Benching checks
                    double time33 = 0.0;// Benching generating values
                    double time4 = 0.0; // Benching the verification process
                    for (int i = 0; i < iterations; i++)
                    {
                        _ProvingAndVerifyingTest11(Exp, keySize, alpha, 128, out double subTime1, out double subTime2, out double subTime3, out double subTime33, out double subTime4);
                        time1 += subTime1;
                        time2 += subTime2;
                        time3 += subTime3;
                        time33 += subTime33;
                        time4 += subTime4;
                    }
                    Console.WriteLine(" ,{0} ,{1} ,Benching setup: {2} ,Benching calculating limits: {3},Benching checks: {4},Benching generating values: {6},Benching the verification process: {5}", alpha, keySize, time1 / iterations, time2 / iterations, time3 / iterations, time4 / iterations, time33 / iterations);
                }
            }
        }

        [TestMethod()]
        public void BenchmarkPermutationTest()
        {
            //var alphaList = new int[6] { 41, 997, 4999, 7649, 20663, 33469 };
            //var keySizeList = new int[3] { 512, 1024, 2048};
            //var alphaList = new int[12] { 43, 991, 1723, 1777, 3391, 3581, 7649, 8663, 20663, 30137, 71471, 352831 }; //Spredsheet values
            //var keySizeList = new int[1] { 2048 }; //Spreadsheet values
            var alphaList = new int[1] { 30137 }; //microBenchmark value
            var keySizeList = new int[1] { 2048 }; //Spreadsheet values
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

        public void _ProvingAndVerifyingTest11(BigInteger Exp, int keySize, int alpha, int k, out double time1, out double time2, out double time3, out double time33, out double time4)
        {
            // PermutationTest Protocol
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);

            PermutationTest.BenchVerifying(pubKey, signature, alpha, keySize, ps, out time1, out time2, out time3, out time33, out time4);
        }

        public void _ProvingAndVerifyingTest12(BigInteger Exp, int keySize, int alpha, int k, out double time1, out double time2)
        {
            // PermutationTest Protocol
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            byte[][] signature = PermutationTest.BenchProving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps, out time1, out time2);

            PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
        }

        public void _ProvingAndVerifyingTest1(BigInteger Exp, int keySize, int alpha, int k, out double ProvingTime, out double VerifyingTime)
        {
            // PermutationTest Protocol
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            sw.Restart(); //Proving start
            byte[][] signature = PermutationTest.Proving(privKey.P, privKey.Q, privKey.PublicExponent, alpha, ps);
            sw.Stop();  //Proving ends

            ProvingTime = sw.Elapsed.TotalSeconds;

            sw.Restart(); //Verifying start
            PermutationTest.Verifying(pubKey, signature, alpha, keySize, ps);
            sw.Stop();  //Verifying stops

            VerifyingTime = sw.Elapsed.TotalSeconds;
        }
        public void _ProvingAndVerifyingTest2(BigInteger Exp, int keySize, int k, out double ProvingTime, out double VerifyingTime)
        {
            // PoupardStern Protocol
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            sw.Restart(); //Proving start
            var outputTuple = PoupardStern.Proving(privKey.P, privKey.Q, privKey.PublicExponent, keySize, ps, k);
            sw.Stop();  //Proving ends

            ProvingTime = sw.Elapsed.TotalSeconds;

            var xValues = outputTuple.Item1;
            var y = outputTuple.Item2;

            sw.Restart(); //Verifying start
            PoupardStern.Verifying(pubKey, xValues, y, keySize, ps, k);
            sw.Stop();  //Verifying stops

            VerifyingTime = sw.Elapsed.TotalSeconds;

        }
        public void _CheckAlphaN(BigInteger Exp, int keySize, int alpha, out double alphaTime)
        {
            var keyPair = new RsaKey(Exp, keySize);

            var privKey = keyPair._privKey;
            var pubKey = new RsaPubKey(keyPair);

            var Modulus = pubKey._pubKey.Modulus;

            sw.Restart(); //Check AlphaN start
            PermutationTest.CheckAlphaN(alpha, Modulus);
            sw.Stop();  //Check AlphaN ends

            alphaTime = sw.Elapsed.TotalSeconds;
        }

    }
}