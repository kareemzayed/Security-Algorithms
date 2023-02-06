using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {

            string cipherText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += Convert.ToChar(((Convert.ToInt16(plainText[i]) - 97 + key) % 26) + 65);

            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";

            for (int i = 0; i < cipherText.Length; i++)
            {

                if ((Convert.ToInt16(cipherText[i]) - 65 - key) < 0)
                {

                    plainText += Convert.ToChar(((Convert.ToInt16(cipherText[i]) - 65 - key) + 26) + 97);

                }
                else
                {
                    plainText += Convert.ToChar(((Convert.ToInt16(cipherText[i]) - 65 - key) % 26) + 97);
                }

            }


            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {

            int key = 0;

            for (int i = 0; i < plainText.Length; i++)
            {

                key = (Convert.ToInt16(cipherText[i]) - Convert.ToInt16(plainText[i]) + 32);
                if (key < 0)
                {
                    key = key + 26;
                }

            }
            return key;
        }
    }
}
