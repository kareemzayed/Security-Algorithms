using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> key = new List<int>();
            int countPT = 0, countCT = 0, col = 0, row = 0;

            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            //if first character in PT = first character in CT
            if (plainText[0] == cipherText[0])
            {
                for (int x = 1; x < plainText.Length; x++)
                {
                    if (cipherText[1] != plainText[x]) col++;
                    else
                    {
                        col++;
                        break;
                    }

                }

                row = cipherText.Length / col;

                if (row * col != cipherText.Length) row++;
            }
            else
            {
                int firstLetter = 0, secondLetter = 0;
                for (int x = 0; x < cipherText.Length; x++)
                {
                    if (plainText[0] == cipherText[x])
                    {
                        firstLetter = x;
                        break;
                    }
                }
                if (firstLetter != 0 && firstLetter + 1 < cipherText.Length)
                {
                    if (plainText[0] == cipherText[firstLetter + 1])
                        firstLetter += 1;
                }

                for (int x = 0; x < cipherText.Length; x++)
                {
                    if (plainText[1] == cipherText[x])
                    {
                        secondLetter = x;
                        break;
                    }

                }
                if (secondLetter != 0 && secondLetter + 1 < cipherText.Length)
                {
                    if (plainText[1] == cipherText[secondLetter + 1])
                        secondLetter += 1;
                }

                row = Math.Abs(firstLetter - secondLetter);
                if (row == 0) row = 1;
                col = cipherText.Length / row;
                if (row * col < cipherText.Length) col++;
            }

            char[,] matrix2DPT = new char[row, col];

            for (int row1 = 0; row1 < row; row1++)
            {
                for (int col1 = 0; col1 < col; col1++)
                {
                    if (countPT < plainText.Length)
                    {
                        matrix2DPT[row1, col1] = plainText[countPT];
                        countPT++;
                    }
                    else break;
                }
            }

            int addXToMatrix = col * row - plainText.Length;
            int diff = col - addXToMatrix;
            if (addXToMatrix != 0)
            {
                for (int i = 0; i < addXToMatrix; i++)
                {
                    if (diff < col)
                    {
                        matrix2DPT[row - 1, diff] = 'X';
                        diff++;
                    }
                    else break;

                }

            }

            char[,] matrix2DCT = new char[row, col];
            int changeRowCT = 0;
            int found = 0;
            countCT = 0;
            for (int colCT = 0; colCT < col; colCT++)
            {
                found = 0;
                for (int rowCT = changeRowCT; rowCT < row; rowCT++)
                {
                    if (countCT < cipherText.Length)
                    {
                        matrix2DCT[rowCT, colCT] = cipherText[countCT];
                        countCT++;
                    }
                    if (rowCT == row - 1)
                    {
                        for (int colPT = 0; colPT < col; colPT++)
                        {
                            if (matrix2DCT[row - 1, colCT] == matrix2DPT[row - 1, colPT])
                            {
                                found = 1;
                                break;
                            }

                        }
                        if (found == 0 && colCT + 1 < col)
                        {
                            char oldCharInMatrix = matrix2DCT[rowCT, colCT];

                            matrix2DCT[rowCT, colCT] = 'X';
                            matrix2DCT[0, colCT + 1] = oldCharInMatrix;
                            changeRowCT = 1;
                        }
                        else if (found == 1) changeRowCT = 0;

                    }
                }
            }

            if (matrix2DCT[row - 1, col - 1] == '\0')
            {
                matrix2DCT[row - 1, col - 1] = 'X';
            }

            int size = 0, save = 0;

            for (int colPT = 0; colPT < col; colPT++)
            {
                for (int colCT = 0; colCT < col; colCT++)
                {
                    for (int rows = 0; rows < row; rows++)
                    {
                        if (matrix2DPT[rows, colPT] == matrix2DCT[rows, colCT])
                        {
                            save = colCT;
                            size++;
                            if (size == row)
                            {
                                key.Add(save + 1);

                            }
                        }
                        else
                        {
                            size = 0;
                            rows = row;
                        }
                    }
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int col = -1, row = 0; ;
            string pt = "";

            row = cipherText.Length / key.Count;

            int[] arr1 = new int[key.Count];
            int c = 1;

            for (int i = 0; i < key.Count; i++)
            {
                if (col < key[i])
                {
                    col = key[i];
                }
            }

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (c == key[j])
                    {
                        arr1[i] = j;
                        c++;
                        break;
                    }
                }

            }


            int countPT = 0;

            char[,] matrix2D = new char[row, col];


            for (int cols = 0; cols < col; cols++)
            {
                for (int rows = 0; rows < row; rows++)
                {
                    if (countPT < cipherText.Length)
                    {
                        matrix2D[rows, cols] = cipherText[countPT];
                        countPT++;
                    }

                }
            }


            char[,] matrix2DNew = new char[row, col];

            for (int cols = 0; cols < col; cols++)
            {
                for (int rows = 0; rows < row; rows++)
                {
                    matrix2DNew[rows, arr1[cols]] = matrix2D[rows, cols];
                }
            }

            for (int rows = 0; rows < row; rows++)
            {

                for (int cols = 0; cols < col; cols++)
                {
                    pt += matrix2DNew[rows, cols];
                }
            }

            return pt.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {

            string cipherText = "";
            int col = -1, row = 0; ;

            for (int i = 0; i < key.Count; i++)
            {
                if (col < key[i])
                {
                    col = key[i];
                }
            }


            int[] arr1 = new int[key.Count];
            int c = 1;

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (c == key[j])
                    {
                        arr1[i] = j;
                        c++;
                        break;
                    }
                }

            }

            row = plainText.Length / col;
            if (row * col != plainText.Length)
            {
                row++;
            }

            int countPT = 0;

            char[,] matrix2D = new char[row, col];

            for (int rows = 0; rows < row; rows++)
            {
                for (int cols = 0; cols < col; cols++)
                {
                    if (countPT < plainText.Length)
                    {
                        matrix2D[rows, cols] = plainText[countPT];
                        countPT++;
                    }
                    else
                    {
                        if (cols < col)
                        {
                            matrix2D[rows, cols] = 'X';
                        }


                    }
                }
            }

            for (int i = 0; i < key.Count; i++)
            {

                for (int j = 0; j < row; j++)
                {
                    cipherText += matrix2D[j, arr1[i]];
                }
            }

            return cipherText.ToUpper();
        }
    }
}
