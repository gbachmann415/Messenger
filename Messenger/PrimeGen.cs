/// Gunnar Bachmann
/// CSCI.251 - Professor Jeremy Brown

using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace Messenger
{
    ///<summary>
    /// Class to generate prime number of a specific size (bits).
    ///</summary>
    public class PrimeGen
    {
        private readonly int _bytes;
        private readonly int _bits;
        private static readonly object primeLock = new ();

        ///<summary>
        /// Stores bits given for size of prime number,
        /// bit amount in bytes, and count of how many 
        /// prime numbers to generate.
        ///</summary>
        public PrimeGen(int bits)
        {
            _bits = bits;
            _bytes = bits/8;
        }

        ///<summary>
        /// Iterator for looping until condition is met.
        ///</summary>
        private static IEnumerable<bool> IterateUntilFalse(Func<bool> condition)
        {
            while(condition()) yield return true;
        }

        ///<summary>
        /// Method to generate a prime numbers of a given size.
        ///</summary>
        ///<returns>Prime number</returns>
        public BigInteger Generate()
        {
            var counter = 0;
            var primeNum = BigInteger.Zero;
            Parallel.ForEach(IterateUntilFalse(() => counter< 1), _ =>
            {
                var num = new BigInteger(RandomNumberGenerator.GetBytes(_bytes));
                num = BigInteger.Abs(num);
                if (BigInteger.ModPow(num, 1, 2) == 0)
                {
                    return;
                }
                if (!num.IsProbablyPrime())
                {
                    return;
                }
                lock (primeLock)
                {
                    if (counter >= 1)
                    {
                        return;
                    }
                    counter++;
                    primeNum = num;
                }
            });
            return primeNum;
        }
    }

    public static class Extensions
    {
        /// <summary>
        /// Extension method to check to see if a number is prime.
        /// Where k is the number of witnesses (10 is the default value and shoudl work
        /// for this project)
        /// </summary>
        /// <param name="value"> value > 3, an odd integer to be tested for primality.</param>
        /// <param name="k"> k, the number of rounds of testing to perform.</param>
        /// <returns> 
        /// "composite" if n is found to be composite, "probably prime" otherwise write
        /// n as (2^r)*d+1 with d odd (by factoring out powers of 2 from n - 1)
        /// </returns> 
        public static bool IsProbablyPrime(this BigInteger value, int k = 10)
        {
            BigInteger rem = BigInteger.Remainder(value, 2);

            // Check corner cases
            if (value < 3){return false;}
            if (rem.Equals(0)){return false;}
            
            // Write n as (2^r)*d+1 with d odd (by factoring out powers of 2 from n - 1)
            var d = value - 1;
            var r = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                r += 1;
            }

            // Create Random Number Generator
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            // Initialize byte array
            byte[] bytes = new byte[value.ToByteArray().Length];
            // Declare variable a
            BigInteger a;

            // WitnessLoop: repeat k times
            for (int i = 0; i < k; i++)
            {
                // pick a random integer a in the range [2, n - 2]
                do
                {
                    rng.GetBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= value - 2);

                // x <-- a^d mod n, ModPow(value, exponent, mod)
                var x = BigInteger.ModPow(a, d, value);
                
                // if x = 1 or x = n - 1 then: continue WitnessLoop
                if (x == 1 || x == value - 1){goto WITNESSLOOP;}
                
                // repeat r - 1 times:
                for (int j = 1; j < r; j++)
                {
                    // x <-- x^2 mod n
                    x = BigInteger.ModPow(x, 2, value);
                    // if x = n - 1 then: continue WitnessLoop
                    if (x == value - 1){goto WITNESSLOOP;}
                    if (x == 1){return false;}
                }
                // return "composite"
                return false;
                WITNESSLOOP:
                    continue;
            }
            // return "probably prime"
            return true;
        }
    }
}