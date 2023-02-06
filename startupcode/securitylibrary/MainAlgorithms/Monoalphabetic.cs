using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        char[] alpha = "abcdefghijklmnopqrstuvwxyz".ToCharArray();

        public string Analyse(string plainText, string cipherText)
        {

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[] key = new char[26];

            int count = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                count = plainText[i] - 97;
                key[count] = cipherText[i];
            }

            IEnumerable<char> diff = alpha.Except(key);

            char[] diffrence = diff.ToArray();
            int counter = 0;
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == 0)
                {
                    key[i] = diffrence[counter];
                    counter++;
                }
            }

            string Key = new string(key);
            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();

            char[] plain = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plain[i] = (char)(j + 97);
                    }
                }

            }
            string plainText = new string(plain); ;
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            char[] CT = new char[plainText.Length];
            int count = 0;
            for (int i = 0; i < plainText.Length;i++)
            {
                count = plainText[i] - 97;
                CT[i] = key[count];

            }
            string ct = new string(CT);

            return ct;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            Dictionary<char, int> AlphabetFreq = new Dictionary<char, int>();
            Dictionary<char, char> PLtable = new Dictionary<char, char>();
            string PL = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!AlphabetFreq.ContainsKey(cipher[i]))
                {
                    AlphabetFreq.Add(cipher[i], 0);
                }
                else
                {
                    AlphabetFreq[cipher[i]]++;
                }
            }
            AlphabetFreq = AlphabetFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            int Coun = 0;
            foreach (var item in AlphabetFreq)
            {
                PLtable.Add(item.Key, "etaoinsrhldcumfpgwybvkxjqz"[Coun]);
                Coun++;
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                PL += PLtable[cipher[i]];
            }
            return PL;
        }
    }
}
