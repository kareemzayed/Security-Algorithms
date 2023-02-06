using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        /// 

        static int gcd(int number, int b)
        {
            int r;

            while (b != 0)
            {
                r = number % b;
                number = b;
                b = r;
            }

            return number;
        }

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            if (gcd(number, baseN) != 1)
                return -1;

            int m0 = baseN;
            int y = 0, x = 1;

            while (number > 1)
            {
                int q = number / baseN;

                int t = baseN;

                baseN = number % baseN;
                number = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }
    }
}
