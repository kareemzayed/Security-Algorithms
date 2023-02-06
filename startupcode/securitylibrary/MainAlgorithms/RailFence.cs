using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            for (int i = 1; i < plainText.Length; i++)
            {
                if (plainText[i] == cipherText[2])
                {
                    key = i;
                    break;
                }
            }
            key = key / 2;
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {

            string PT = "";
            int NumberOfColumn = cipherText.Length / key;
            int c = 0;
            int b = 0;

            for (int x = 0; x < cipherText.Length; x++)
            {
                if (cipherText[x] == 'X')
                {
                    c++;
                    b = 1;
                }
            }

            if (b == 1)
            {

                NumberOfColumn = (cipherText.Length - c) / key;


                if (cipherText.Length - c % 2 != 0)
                {
                    NumberOfColumn++;
                }

            }
            else
            {
                if (cipherText.Length % 2 != 0)
                {
                    NumberOfColumn++;
                }
            }

            char[,] Matrix2D = new char[key, NumberOfColumn];
            int count = 0;
            for (int x = 0; x < key; x++)
            {
                for (int y = 0; y < NumberOfColumn; y++)
                {
                    if (count < cipherText.Length)
                    {
                        Matrix2D[x, y] = cipherText[count];
                        count++;
                    }
                }
            }
            for (int x = 0; x < NumberOfColumn; x++)
            {
                for (int y = 0; y < key; y++)
                {

                    PT += Matrix2D[y, x];

                }
            }

            return PT.ToLower();

        }

        public string Encrypt(string plainText, int key)
        {
            string CT = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i].Equals(" "))
                {
                    plainText.Remove(i, 1);
                }
            }
            int NumberOfColumn = plainText.Length / key;
            if (plainText.Length % 2 != 0)
            {
                NumberOfColumn++;
            }
            char[,] Matrix2D = new char[key, NumberOfColumn];
            int count = 0;
            for (int col = 0; col < NumberOfColumn; col++)
            {
                for (int row = 0; row < key; row++)
                {
                    if (count < plainText.Length)
                    {
                        Matrix2D[row, col] = plainText[count];
                        count++;
                    }

                }
            }

            for (int row = 0; row < key; row++)
            {
                for (int col = 0; col < NumberOfColumn; col++)
                {
                    CT += Matrix2D[row, col];

                }
            }
            return CT.ToUpper();
        }
    }
}