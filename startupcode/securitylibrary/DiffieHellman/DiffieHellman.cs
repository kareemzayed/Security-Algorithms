using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int PowerFunction(int Base, int power, int mod)
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * Base) % mod;
            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            //x is a private key -> we want to calc public key for a and b
            int pub_of_a = PowerFunction(alpha, xa, q);
            int pub_of_b = PowerFunction(alpha, xb, q);
            int key_A = PowerFunction(pub_of_b, xa, q);
            int key_B = PowerFunction(pub_of_a, xb, q);
            List<int> res = new List<int>();
            res.Add(key_A);
            res.Add(key_B);
            return res;
        }
    }
}
