using System;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        int[] numbOfBits = new int[16] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        int[,] PermutedChoice1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9},
                                                   { 1, 58, 50, 42, 34, 26, 18},
                                                   { 10, 2, 59, 51, 43, 35, 27},
                                                   { 19, 11, 3, 60, 52, 44, 36},
                                                   { 63, 55, 47, 39, 31, 23, 15},
                                                   { 7, 62, 54, 46, 38, 30, 22},
                                                   { 14, 6, 61, 53, 45, 37, 29},
                                                   { 21, 13, 5, 28, 20, 12, 4}};

        int[,] PermutedChoice2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 },
                                                   { 3, 28, 15, 6, 21, 10 },
                                                   { 23, 19, 12, 4, 26, 8 },
                                                   { 16, 7, 27, 20, 13, 2 },
                                                   { 41, 52, 31, 37, 47, 55 },
                                                   { 30, 40, 51, 45, 33, 48 },
                                                   { 44, 49, 39, 56, 34, 53 },
                                                   { 46, 42, 50, 36, 29, 32 } };

        int[,] initailPer = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

        int[,] E_Bit = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
        int[,] inversePer = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

        public static int[,] sb1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        public static int[,] sb2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        public static int[,] sb3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        public static int[,] sb4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        public static int[,] sb5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        public static int[,] sb6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        public static int[,] sb7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        public static int[,] sb8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        public static int[,] Ppermutation = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

        //Helper Functions
        public static string LeftCircularShift(string key, int shift)
        {
            shift %= key.Length;
            return key.Substring(shift) + key.Substring(0, shift);
        }

        public static string expandR(string R, int[,] E_Bit)
        {
            int y = 0;
            string expandedR = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    expandedR += R[E_Bit[i, j] - 1];
                    y++;
                }
            }

            return expandedR;
        }

        
        public static string mangler(string expandedR, string Key)
        {
            string res = XorOperation(expandedR, Key);

            string reductedres = reduceRes(res);

            string permutedres = permuteRes(reductedres);

            return permutedres;
        }

        public static string permuteRes(string redRes)
        {
            string res = "";
            int u = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res += redRes[Ppermutation[i, j] - 1];
                    u++;
                }
            }

            return res;

        }


        public static string reduceRes(string res)
        {
            string[] blocks = new string[8];

            blocks[0] = res.Substring(0, 6);
            blocks[1] = res.Substring(6, 6);
            blocks[2] = res.Substring(12, 6);
            blocks[3] = res.Substring(18, 6);
            blocks[4] = res.Substring(24, 6);
            blocks[5] = res.Substring(30, 6);
            blocks[6] = res.Substring(36, 6);
            blocks[7] = res.Substring(42, 6);

            string[] newBlocks = new string[8];


            int row, col;
            for (int i = 1; i <= 8; i++)
            {
                string c;
                char[] r = new char[2];
                if (i == 1)
                {
                    r[0] = blocks[0][0];
                    r[1] = blocks[0][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[0].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[0] = Convert.ToString(sb1[row, col], 2).PadLeft(4, '0');
                }

                else if (i == 2)
                {
                    r[0] = blocks[1][0];
                    r[1] = blocks[1][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[1].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[1] = Convert.ToString(sb2[row, col], 2).PadLeft(4, '0');
                }
                else if (i == 3)
                {
                    r[0] = blocks[2][0];
                    r[1] = blocks[2][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[2].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[2] = Convert.ToString(sb3[row, col], 2).PadLeft(4, '0');
                }
                else if (i == 4)
                {
                    r[0] = blocks[3][0];
                    r[1] = blocks[3][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[3].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[3] = Convert.ToString(sb4[row, col], 2).PadLeft(4, '0');
                }
                else if (i == 5)
                {
                    r[0] = blocks[4][0];
                    r[1] = blocks[4][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[4].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[4] = Convert.ToString(sb5[row, col], 2).PadLeft(4, '0');
                }
                else if (i == 6)
                {
                    r[0] = blocks[5][0];
                    r[1] = blocks[5][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[5].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[5] = Convert.ToString(sb6[row, col], 2).PadLeft(4, '0');
                }
                else if (i == 7)
                {
                    r[0] = blocks[6][0];
                    r[1] = blocks[6][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[6].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[6] = Convert.ToString(sb7[row, col], 2).PadLeft(4, '0');
                }
                else if (i == 8)
                {
                    r[0] = blocks[7][0];
                    r[1] = blocks[7][5];
                    string roww = new string(r);
                    row = Convert.ToInt32(roww, 2);
                    c = blocks[7].Substring(1, 4);
                    col = Convert.ToInt32(c, 2);
                    newBlocks[7] = Convert.ToString(sb8[row, col], 2).PadLeft(4, '0');
                }

            }

            string ff = "";
            for (int i = 0; i < 8; i++)
                ff += newBlocks[i];

            return ff;
        }

        private static string XorOperation(string bin1, string bin2)
        {
            int len = Math.Max(bin1.Length, bin2.Length);
            string res = "";
            bin1 = bin1.PadLeft(len, '0');
            bin2 = bin2.PadLeft(len, '0');

            for (int i = 0; i < len; i++)
                res += bin1[i] == bin2[i] ? '0' : '1';
            return res;
        }



        public override string Decrypt(string cipherText, string key)
        {
            string binaryKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            string binaryCipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');

            int q = 0;
            string permutedKey1 = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutedKey1 += binaryKey[PermutedChoice1[i, j] - 1];
                    q++;
                }
            }

            //Cropping C0 and D0 from the permuted Key
            string c0 = permutedKey1.Substring(0, 28);
            string d0 = permutedKey1.Substring(28, 28);

            //Circular shift left for all D's and C's
            string[] all_C = new string[16];
            string[] all_D = new string[16];

            for (int i = 0; i < 16; i++)
            {
                if (i == 0)
                {
                    all_C[i] = LeftCircularShift(c0, numbOfBits[i]);
                    all_D[i] = LeftCircularShift(d0, numbOfBits[i]);
                }
                else
                {
                    all_C[i] = LeftCircularShift(all_C[i - 1], numbOfBits[i]);
                    all_D[i] = LeftCircularShift(all_D[i - 1], numbOfBits[i]);
                }

            }

            //Generating the 16 key
            string[] allKeys = new string[16];
            int x = 0;

            for (int z = 0; z < 16; z++)
            {
                string permutedKey2 = "";
                for (int i = 0; i < 8; i++)
                {
                    string combined = "";
                    for (int j = 0; j < 6; j++)
                    {
                        combined = all_C[z] + all_D[z];
                        permutedKey2 += combined[PermutedChoice2[i, j] - 1];
                        x++;
                    }
                }
                allKeys[z] = permutedKey2;
            }



            //starting from her the Decryption
            int w = 0;
            string permutedCipher = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    permutedCipher += binaryCipher[initailPer[i, j] - 1];
                    w++;
                }
            }

            string R16 = permutedCipher.Substring(0, 32);
            string L16 = permutedCipher.Substring(32, 32);

            //generating all L's And R's
            string[] all_L = new string[16];
            string[] all_R = new string[16];

            //Figure out the inverse
            for (int i = 15; i >= 0; i--)
            {
                if (i == 15)
                {
                    all_R[i] = L16;
                    all_L[i] = XorOperation(R16, mangler(expandR(all_R[i], E_Bit), allKeys[i]));
                }

                else
                {
                    all_R[i] = all_L[i + 1];
                    all_L[i] = XorOperation(all_R[i + 1], mangler(expandR(all_R[i], E_Bit), allKeys[i]));
                }
            }


            string finalRes = all_L[0] + all_R[0];
            string pt = "";
            int u = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    pt += finalRes[inversePer[i, j] - 1];
                    u++;
                }
            }

            string plainText = "0x" + Convert.ToInt64(pt, 2).ToString("X").PadLeft(16,'0');

            return plainText; 
        }




        public override string Encrypt(string plainText, string key)
        {
            string binarykey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            string binaryPlain = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');

            int q = 0;
            string permutedKey1 = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutedKey1 += binarykey[PermutedChoice1[i, j] - 1];
                    q++;
                }
            }

            //Cropping C0 and D0 from the permuted Key
            string c0 = permutedKey1.Substring(0, 28);
            string d0 = permutedKey1.Substring(28, 28);

            //Circular shift left for all D's and C's
            string[] all_C = new string[16];
            string[] all_D = new string[16];

            for (int i = 0; i < 16; i++)
            {
                if (i == 0)
                {
                    all_C[i] = LeftCircularShift(c0, numbOfBits[i]);
                    all_D[i] = LeftCircularShift(d0, numbOfBits[i]);
                }
                else
                {
                    all_C[i] = LeftCircularShift(all_C[i - 1], numbOfBits[i]);
                    all_D[i] = LeftCircularShift(all_D[i - 1], numbOfBits[i]);
                }

            }

            //Generating the 16 key
            string[] allKeys = new string[16];
            int x = 0;

            for (int z = 0; z < 16; z++)
            {
                string permutedKey2 = "";
                for (int i = 0; i < 8; i++)
                {
                    string combined = "";
                    for (int j = 0; j < 6; j++)
                    {
                        combined = all_C[z] + all_D[z];
                        permutedKey2 += combined[PermutedChoice2[i, j] - 1];
                        x++;
                    }
                }
                allKeys[z] = permutedKey2;
            }
            
            //Permutation of the plain text
            int w = 0;
            string permutedPlain = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    permutedPlain += binaryPlain[initailPer[i, j] - 1];
                    w++;
                }
            }

            //Cropping L0,R0 from the permuted plain
            string L0 = permutedPlain.Substring(0, 32);
            string R0 = permutedPlain.Substring(32, 32);


            //generating all L's And R's
            string[] all_L = new string[16];
            string[] all_R = new string[16];

            for (int i = 0; i < 16; i++)
            {
                if (i == 0)
                {
                    all_L[i] = R0;
                    all_R[i] = XorOperation(L0, mangler(expandR(R0, E_Bit), allKeys[i]));
                }
                else
                {
                    all_L[i] = all_R[i - 1];
                    all_R[i] = XorOperation(all_L[i - 1], mangler(expandR(all_R[i - 1], E_Bit), allKeys[i]));
                }
            }


            //Permuting the R16+L16 to get the cihper text
            string finalRes = all_R[15] + all_L[15];
            string ct = "";
            int u = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ct += finalRes[inversePer[i, j] - 1];
                    u++;
                }
            }

            string cipherText = "0x" + Convert.ToInt64(ct, 2).ToString("X").PadLeft(16,'0');

            return cipherText;
        }
    }
}