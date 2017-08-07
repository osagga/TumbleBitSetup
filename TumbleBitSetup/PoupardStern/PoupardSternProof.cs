using System;
using Org.BouncyCastle.Math;

namespace TumbleBitSetup
{
    public class PoupardSternProof
    {
        public PoupardSternProof(Tuple<BigInteger[], BigInteger> proof)
        {
            if(proof == null)
                throw new ArgumentNullException(nameof(proof));
            XValues = proof.Item1;
            YValue = proof.Item2;
        }
        public BigInteger[] XValues
        {
            get; set;
        }
        public BigInteger YValue
        {
            get; set;
        }
    }
}