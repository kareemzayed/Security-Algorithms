using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES orignalDES = new DES();
            string plainText = orignalDES.Decrypt(cipherText, key[1]);
            plainText = orignalDES.Encrypt(plainText, key[0]);
            plainText = orignalDES.Decrypt(plainText, key[1]);

            return plainText;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES orignalDES = new DES();
            string cipherText = orignalDES.Encrypt(plainText, key[0]);
            cipherText = orignalDES.Decrypt(cipherText, key[1]);
            cipherText = orignalDES.Encrypt(cipherText, key[0]);

            return cipherText;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
