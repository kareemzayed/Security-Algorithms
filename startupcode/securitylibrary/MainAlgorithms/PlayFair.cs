using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string pln = "";
            key = key.ToUpper();
            //remove duplicated letters
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {

                    if (key[i] == key[j] && j != i)
                    {
                        key = key.Remove(j, 1);
                    }
                }
            }
            char[,] matrix2D = new char[5, 5];
            //Array of characters
            char[] alpa = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            int index = 0;
            int rowF = key.Length / 5, colF = key.Length % 5;
            //create matrix
            for (int y = 0; y < 5; y++)
            {
                for (int q = 0; q < 5; q++)
                {
                    if (index < key.Length)
                    {
                        matrix2D[y, q] = Convert.ToChar(key[index]);
                        index++;
                    }
                }
            }

            int bo = 0;

            for (int z = 0; z < alpa.Length; z++)
            {
                bo = 0;
                for (int a = 0; a < key.Length; a++)
                {
                    if (alpa[z].Equals(key[a]))
                    {
                        bo = 1;
                    }
                }

                if (bo == 0)
                {
                    matrix2D[rowF, colF] = Convert.ToChar(alpa[z]);

                    colF++;
                    if (colF == 5)
                    {
                        rowF++;
                        colF = 0;

                    }

                }
            }
            cipherText = cipherText.ToUpper();
            StringBuilder edit = new StringBuilder(cipherText.ToUpper()); //we can expand and resize Capacity of string
            edit = edit.Replace("J", "I");
            int checkJ = 0;

            for (int i = 0; i < edit.Length; i++)
            {
                if (edit[i] == 'J')
                {
                    checkJ = 1;
                }
            }

            //count how much letters duplicated
            int count = 0;
            for (int w = 0; w < edit.Length - 1; w += 2)
            {
                if (edit[w] == edit[w + 1] && w + 1 < edit.Length)
                {
                    count++;
                }
            }
            for (int count1 = 0; ((count1 < edit.Length) && ((count1 + 1) < edit.Length)); count1 += 2)
            {
                if (edit[count1] == edit[count1 + 1])
                {
                    edit.Insert(count1 + 1, "X");
                }
            }
            if ((edit.Length % 2) == 1)
            {
                edit.Append("X");
            }



            char FirstLetter, SecondLetter; //2 character
            int FirstPossition_X = 0, SecondPossition_X = 0;
            int FirstPossition_Y = 0, SecondPossition_Y = 0;

            for (int e = 0; e < edit.Length; e += 2)
            {
                FirstLetter = edit[e];
                SecondLetter = edit[e + 1];

                if (checkJ == 1)
                {
                    for (int t = 0; t < 5; t++)
                    {
                        for (int f = 0; f < 5; f++)
                        {
                            if (matrix2D[t, f] == 'I')
                            {
                                matrix2D[t, f] = 'J';
                            }
                        }
                    }
                }
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (FirstLetter == matrix2D[row, col])
                        {
                            FirstPossition_X = row;
                            FirstPossition_Y = col;
                        }
                        if (SecondLetter == matrix2D[row, col])
                        {
                            SecondPossition_X = row;
                            SecondPossition_Y = col;
                        }
                    }
                }




                if (FirstPossition_X == SecondPossition_X)
                {

                    FirstPossition_Y = (FirstPossition_Y - 1) % 5;
                    SecondPossition_Y = (SecondPossition_Y - 1) % 5;

                    if (FirstPossition_Y == -1)
                        FirstPossition_Y = 4;
                    else if (SecondPossition_Y == -1)
                        SecondPossition_Y = 4;


                    pln += matrix2D[FirstPossition_X, FirstPossition_Y];
                    pln += matrix2D[SecondPossition_X, SecondPossition_Y];
                }
                else if (FirstPossition_Y == SecondPossition_Y)
                {


                    FirstPossition_X = (FirstPossition_X - 1) % 5;
                    SecondPossition_X = (SecondPossition_X - 1) % 5;


                    if (FirstPossition_X == -1)
                        FirstPossition_X = 4;
                    else if (SecondPossition_X == -1)
                        SecondPossition_X = 4;

                    pln += matrix2D[FirstPossition_X, FirstPossition_Y];
                    pln += matrix2D[SecondPossition_X, SecondPossition_Y];

                }
                else
                {
                    pln += matrix2D[FirstPossition_X, SecondPossition_Y];
                    pln += matrix2D[SecondPossition_X, FirstPossition_Y];
                }

            }

            string returnedPln = pln;

            if (pln[pln.Length -1] == 'X')
                returnedPln = returnedPln.Remove(pln.Length - 1);

            int o = 0 , h = 0;

            while ( h < returnedPln.Length)
            {
                if (pln[h] == 'X'){
                    if (pln[h - 1] == pln[h + 1])
                    {
                        if (h + o < returnedPln.Length && (h - 1) % 2 == 0)
                        {
                            returnedPln = returnedPln.Remove(h + o, 1);
                            o--;
                        }
                    }
                }
                h++;
            }
            return returnedPln;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            key = key.ToUpper();
            //remove duplicated letters
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {

                    if (key[i] == key[j] && j != i)
                    {
                        key = key.Remove(j, 1);
                    }
                }
            }
            char[,] matrix2D = new char[5, 5];
            //Array of characters
            char[] alpa = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            int index = 0;
            int rowF = key.Length / 5, colF = key.Length % 5;
            //create matrix
            for (int y = 0; y < 5; y++)
            {
                for (int q = 0; q < 5; q++)
                {
                    if (index < key.Length)
                    {
                        matrix2D[y, q] = Convert.ToChar(key[index]);
                        index++;
                    }
                }
            }

            int bo = 0;
            
            for (int z = 0; z < alpa.Length; z++)
            {
                bo = 0;
                for (int a = 0; a < key.Length; a++)
                {
                    if (alpa[z].Equals(key[a]))
                    {
                        bo = 1;
                    }
                }

                if (bo == 0)
                {
                    matrix2D[rowF, colF] = Convert.ToChar(alpa[z]);

                    colF++;
                    if (colF == 5)
                    {
                        rowF++;
                        colF = 0;

                    }

                }
            }
            plainText = plainText.ToUpper();
            StringBuilder edit = new StringBuilder(plainText.ToUpper()); //we can expand and resize Capacity of string
            edit = edit.Replace("J", "I");
            int checkJ = 0;

            for (int i = 0; i < edit.Length; i++)
            {
                if (edit[i] == 'J')
                {
                    checkJ = 1;
                }
            }

            //count how much letters duplicated
            int count = 0;
            for (int w = 0; w < edit.Length - 1; w += 2)
            {
                if (edit[w] == edit[w + 1] && w + 1 < edit.Length)
                {
                    count++;
                }
            }
            for (int count1 = 0; ((count1 < edit.Length) && ((count1 + 1) < edit.Length)); count1 += 2)
            {
                if (edit[count1] == edit[count1 + 1])
                {
                    edit.Insert(count1 + 1, "X");
                }
            }
            if ((edit.Length % 2) == 1)
            {
                edit.Append("X");
            }
            

            char FirstLetter, SecondLetter; //2 character
            int FirstPossition_X = 0, SecondPossition_X = 0;
            int FirstPossition_Y = 0, SecondPossition_Y = 0;

            for (int e = 0; e < edit.Length; e += 2)
            {
                FirstLetter = edit[e];
                SecondLetter = edit[e + 1];

                if (checkJ == 1)
                {
                    for (int t = 0; t < 5; t++)
                    {
                        for (int f = 0; f < 5; f++)
                        {
                            if (matrix2D[t, f] == 'I')
                            {
                                matrix2D[t, f] = 'J';
                            }
                        }
                    }
                }

                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (FirstLetter == matrix2D[row, col])
                        {
                            FirstPossition_X = row;
                            FirstPossition_Y = col;
                        }
                        if (SecondLetter == matrix2D[row, col])
                        {
                            SecondPossition_X = row;
                            SecondPossition_Y = col;
                        }
                    }
                }
                if (FirstPossition_X == SecondPossition_X)
                {
                    FirstPossition_Y = (FirstPossition_Y + 1) % 5;
                    SecondPossition_Y = (SecondPossition_Y + 1) % 5;
                    cipherText += matrix2D[FirstPossition_X, FirstPossition_Y];
                    cipherText += matrix2D[SecondPossition_X, SecondPossition_Y];
                }
                else if (FirstPossition_Y == SecondPossition_Y)
                {
                    FirstPossition_X = (FirstPossition_X + 1) % 5;
                    SecondPossition_X = (SecondPossition_X + 1) % 5;
                    cipherText += matrix2D[FirstPossition_X, FirstPossition_Y];
                    cipherText += matrix2D[SecondPossition_X, SecondPossition_Y];
                }
                else
                {
                    cipherText += matrix2D[FirstPossition_X, SecondPossition_Y];
                    cipherText += matrix2D[SecondPossition_X, FirstPossition_Y];
                }
            }
            return cipherText;
        }
    }
}