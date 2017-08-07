using Org.BouncyCastle.Math;
using System;
using System.Linq;
using Org.BouncyCastle.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;

namespace TumbleBitSetup.Tests
{
    [TestClass()]
    public class SamplesData
    {
        // This class generates datasets for testing

        public byte[] ps = Strings.ToByteArray("public string");
        BigInteger Exp = BigInteger.Three;
        int keySize = 128;
        int k = 128;
        int BigK = 129;
        int sampels = 10000;

        [TestMethod()]
        public void GetW_Data()
        {
            var keyPair = Utils.GeneratePrivate(Exp, keySize);

            var pubKey = (RsaKeyParameters)keyPair.Public;
            BigK = 5000;

            var Modulus = pubKey.Modulus;

            BigInteger[] Datalist = new BigInteger[BigK];

            // Initialize list of z values
            BigInteger[] zValues = new BigInteger[BigK];

            // Generate the list of z Values
            for (int i = 0; i < BigK; i++)
                zValues[i] = PoupardStern.SampleFromZnStar(pubKey, ps, i, BigK, keySize);

            for (int i = 0; i < BigK; i++)
            {
                    // Initialize list of x values.
                    BigInteger[] xValues = new BigInteger[BigK];

                    // Generate r
                    PoupardStern.GetR(keySize, out BigInteger r);

                    for (int j = 0; j < BigK; j++)
                        // Compute x_i
                        xValues[j] = zValues[j].ModPow(r, Modulus);

                    // Compute w
                    PoupardStern.GetW(pubKey, ps, xValues, k, keySize, out BigInteger w);

                    Datalist[i] = w;
            }
            Console.WriteLine(String.Join(",", Datalist.ToList()));
        }

        [TestMethod()]
        public void GetR_Data()
        {

            var list = new BigInteger[sampels];

            for (int i = 0; i < sampels; i++)
                PoupardStern.GetR(keySize, out list[i]);

            Console.WriteLine(String.Join(",", list.ToList()));
        }

        [TestMethod()]
        public void SampleFromZnStar_Data()
        {
            BigK = sampels;
            var keyPair = Utils.GeneratePrivate(Exp, keySize);
            var pubKey = (RsaKeyParameters)keyPair.Public;

            var Modulus = pubKey.Modulus;

            var list = new BigInteger[sampels];

            for (int i = 0; i < sampels; i++)
                list[i] = PoupardStern.SampleFromZnStar(pubKey, ps, i, BigK, keySize);

            Console.WriteLine(String.Join(",", list.ToList()));
        }

        [TestMethod()]
        public void GetRhos_Data()
        {
            // GetRhos is really producing outputs rho that are<N and have GCD(N, rho) = 1
            int m2 = 10000;
            var keyPair = Utils.GeneratePrivate(Exp, keySize);

            var privKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
            var pubKey = (RsaKeyParameters)keyPair.Public;

            var Modulus = pubKey.Modulus;

            // Generate list of rho values
            PermutationTest.GetRhos(m2, ps, pubKey, keySize, out byte[][] rhoValues);

            Console.WriteLine(String.Join(",", rhoValues.Select(a => new BigInteger(1, a))));
        }

    }
}
