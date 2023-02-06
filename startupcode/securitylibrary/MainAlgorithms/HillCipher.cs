using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> sampleKey;
            int[] sample;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            sample = new int[] { i, j, k, l };
                            sampleKey = new List<int>(sample);

                            List<int> resultCipher = Encrypt(plainText, sampleKey);

                            if (resultCipher.SequenceEqual(cipherText))
                            {
                                return sampleKey;
                            }

                        }
                    }
                }
            }
            throw new InvalidAnlysisException();

        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            int rowCol;
            if (key.Count != 4)
                rowCol = 3;
            else
                rowCol = 2;
            int[,] keytemp = new int[rowCol, rowCol];
            int[,] ciphwrtext = new int[rowCol, 1];
            int counter = 0;
            for (int i = 0; i < rowCol; i++)
            {
                for (int j = 0; j < rowCol; j++)
                {
                    keytemp[i, j] = key[counter];
                    counter++;
                }
            }

            int[,] inverse_key = find_inv_key(keytemp);

            for (int i = 0; i < cipherText.Count; i += rowCol)
            {
                for (int j = i, x = 0; j < i + rowCol; j++, x++)
                {
                    ciphwrtext[x, 0] = cipherText[j];
                }

                // calculate matrix multiblication
                ///////////////////////
                int[,] PT = new int[rowCol, 1];
                for (int k = 0; k < rowCol; k++)
                {
                    for (int j = 0; j < 1; j++)
                    {
                        for (int x = 0; x < rowCol; x++)
                        {
                            PT[k, j] += (inverse_key[k, x] * ciphwrtext[x, j]);
                        }
                        PT[k, j] %= 26;
                    }
                }

                for (int q = 0; q < rowCol; q++)
                {
                    plainText.Add(PT[q, 0]);
                }
            }

            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> ciphertext = new List<int>();
            int m = 0;
            int counter = 0;
            if (key.Count == 9)
            {
                m = 3;
            }
            else
            {
                m = 2;
            }
            int[,] key_matrix = new int[m, m];
            int[,] plaintext_matrix = new int[m, 1];
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    key_matrix[i, j] = key[counter++];
                }

            }
            for (int i = 0; i < plainText.Count; i += m)
            {
                int rows = 0;
                for (int j = i; j < (i + m); j++)
                {
                    plaintext_matrix[rows, 0] = plainText[j];
                    rows++;
                }

                int[,] ciphertext_matrix = MatMultiplication(key_matrix, plaintext_matrix, m, m, 1);
                int k = 0;
                while (k < m)
                {
                    ciphertext.Add(ciphertext_matrix[k, 0]);
                    k++;
                }
            }
            return ciphertext;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plainText , List<int> cipherText)
        {
            List<double> cipherDouble = cipherText.ConvertAll(x => (double)x);
            List<double> plainDouble = plainText.ConvertAll(x => (double)x);

            int rows = (int)Math.Sqrt((cipherDouble.Count));
            int col = cipherText.Count / rows;

            Matrix<double> cipherMatrix = DenseMatrix.OfColumnMajor(rows, col, cipherDouble);
            Matrix<double> plainMatrix = DenseMatrix.OfColumnMajor(rows, col, plainDouble);
            List<int> sampleKey = new List<int>();
            Matrix<double> keyMatrix = DenseMatrix.Create(3, 3, 0);

            int det0 = (int)plainMatrix.Determinant();
            int mulInverse = multiplicativeInverse(det0);

            plainMatrix = plainInverse(plainMatrix, mulInverse);

            keyMatrix = cipherMatrix.Multiply(plainMatrix);

            sampleKey = keyMatrix.Transpose().Enumerate().Select(i => (int)i % 26).ToList();
            return sampleKey;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        //Additional functions

        public int[,] MatMultiplication(int[,] a, int[,] b, int row1, int colum1, int colum2)
        {
            int[,] result = new int[row1, colum2];

            for (int i = 0; i < row1; i++)
            {
                for (int j = 0; j < colum2; j++)
                {
                    for (int k = 0; k < colum1; k++)
                    {
                        result[i, j] += (a[i, k] * b[k, j]);
                    }
                    result[i, j] %= 26;
                }
            }
            return result;
        }

        public Matrix<double> plainInverse(Matrix<double> plainMat, int A)
        {
            plainMat = plainMat.Transpose();
            int r, c, r1, c1;
            double p;
            Matrix<double> resMat = DenseMatrix.Create(3, 3, 0.0);

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (i == 0)
                        r = 1;
                    else
                        r = 0;

                    if (j == 0)
                        c = 1;
                    else
                        c = 0;

                    if (i == 2)
                        r1 = 1;
                    else
                        r1 = 2;

                    if (j == 2)
                        c1 = 1;
                    else
                        c1 = 2;


                    p = ((plainMat[r, c] * plainMat[r1, c1] - plainMat[r, c1] * plainMat[r1, c]) * Math.Pow(-1, i + j) * A) % 26;
                    if (p < 0)
                        resMat[i, j] = p + 26;
                    else
                        resMat[i, j] = p;

                    
                }
            }
            return resMat;
        }
  
        public int multiplicativeInverse(int det)
        {
            for (int i = 0; i < 26; i++)
            {
                if (det * i % 26 == 1)
                {
                    return i;
                }
            }

            throw new InvalidAnlysisException();
        }

        public int[,] find_inv_key(int[,] k)
        {
            
            int Determinatn;
            // calculate determinant
            if (k.Length == 4)
                Determinatn = (k[0, 0] * k[1, 1]) - (k[0, 1] * k[1, 0]);
            else
                Determinatn = k[0, 0] * (k[1, 1] * k[2, 2] - k[1, 2] * k[2, 1]) - k[0, 1] * (k[1, 0] * k[2, 2] - k[1, 2] * k[2, 0]) + k[0, 2] * (k[1, 0] * k[2, 1] - k[1, 1] * k[2, 0]);
            if (Determinatn > 0)
                Determinatn %= 26;
            else
                Determinatn = (Determinatn % 26) + 26;

            // Get the Modular multiplicative inverse of det(keytemp)
            int modulaMultiInv = multiplicativeInverse(Determinatn);
            

            // Get the inverse key if the matrix is 2*2
            if (k.Length == 4)
            {
                int x = 1 / (k[0, 0] * k[1, 1] - k[0, 1] * k[1, 0]);
                int[,] inversekey2 = new int[2, 2];
                inversekey2[0, 0] = (k[1, 1] * x) % 26;
                inversekey2[1, 1] = (k[0, 0] * x) % 26;
                inversekey2[0, 1] = (-1 * k[0, 1] * x) % 26;
                inversekey2[1, 0] = (-1 * k[1, 0] * x) % 26;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        if (inversekey2[i, j] < 0)
                            inversekey2[i, j] += 26;
                    }
                }
                return inversekey2;
            }

            // Get the inverse key if the matrix is 3*3
            int[,] inverseKey3 = new int[3, 3];

            inverseKey3[0, 0] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)0) * ((k[1, 1] * k[2, 2] - k[1, 2] * k[2, 1]) % 26)) % 26;
            inverseKey3[0, 1] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)1) * ((k[1, 0] * k[2, 2] - k[1, 2] * k[2, 0]) % 26)) % 26;
            inverseKey3[0, 2] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)2) * ((k[1, 0] * k[2, 1] - k[1, 1] * k[2, 0]) % 26)) % 26;

            inverseKey3[1, 0] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)1) * ((k[0, 1] * k[2, 2] - k[0, 2] * k[2, 1]) % 26)) % 26;
            inverseKey3[1, 1] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)2) * ((k[0, 0] * k[2, 2] - k[0, 2] * k[2, 0]) % 26)) % 26;
            inverseKey3[1, 2] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)3) * ((k[0, 0] * k[2, 1] - k[0, 1] * k[2, 0]) % 26)) % 26;

            inverseKey3[2, 0] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)2) * ((k[0, 1] * k[1, 2] - k[0, 2] * k[1, 1]) % 26)) % 26;
            inverseKey3[2, 1] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)3) * ((k[0, 0] * k[1, 2] - k[0, 2] * k[1, 0]) % 26)) % 26;
            inverseKey3[2, 2] = (modulaMultiInv * (int)Math.Pow((int)-1, (int)4) * ((k[0, 0] * k[1, 1] - k[0, 1] * k[1, 0]) % 26)) % 26;

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (inverseKey3[i, j] < 0)
                        inverseKey3[i, j] += 26;
                }
            }

            int[,] InvKey = new int[3, 3];
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 3; i++)
                {
                    InvKey[j, i] = inverseKey3[i, j];
                }
            }
            return InvKey;
        }

           

    }
}
