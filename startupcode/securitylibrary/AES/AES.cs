using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private static string[] SBOX = {
            "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
            "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
            "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
            "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
            "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
            "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
            "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
            "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
            "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
            "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
            "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
            "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
            "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
            "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
            "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
            "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
        };
        private static byte[] iSBOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };
        public static string[] mixCols = {
        "02", "03", "01", "01",
        "01", "02", "03", "01",
        "01", "01", "02", "03",
        "03", "01", "01", "02"
        };
        public static string[] Rcon = {
        "01","02","04","08","10","20","40","80","1B","36" ,"00","00","00","00","00","00","00","00","00","00" ,
        "00","00","00","00","00","00","00","00","00","00" ,"00","00","00","00","00","00","00","00","00","00"
        };

        public static string[] EditRow(string[] m, int j)
        {
            string[] matrix = new string[4];
            for (int i = 0; i < 4; i++)
                matrix[i] = m[(i + j) % 4];

            return matrix;
        }
        public static string[] Edit_Column(string[,] x)
        {
            string[] sub_array = new string[4];
            for (int i = 0; i < 4; i++)
                sub_array[i] = x[(i + 1) % 4, 3];

            return sub_array;
        }
        public static string[,] EditLastColumn(string[,] m)
        {
            string[,] matrix = new string[4, 1];
            for (int i = 0; i < 4; i++)
                matrix[i, 0] = m[(i + 1) % 4, 0];
            return matrix;
        }
        public static string EditMatrixBinaryShift(string x)
        {
            string sub_array = "";
            for (int i = 0; i < x.Length; i++)
                sub_array = sub_array + x[(i + 1) % x.Length];

            return sub_array;
        }
        public static string[,] Shift_Rows(string[,] matrix)
        {
            int row = 0;
            string[] x = new string[4];
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                    x[i] = matrix[row, i];

                x = EditRow(x, j);

                for (int z = 0; z < 4; z++)
                    matrix[row, z] = x[z];

                row++;
            }
            return matrix;
        }
        public static string[,] Generate_Matrix(string x)
        {
            string[,] key_matrix = new string[4, 4];
            int counter = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    key_matrix[j, i] = Convert.ToString(x[counter]);
                    counter++;
                    key_matrix[j, i] += Convert.ToString(x[counter]);
                    counter++;
                }
            }
            return key_matrix;
        }
        public static string To_Binary(string str)
        {
            //convert from hexa to binary
            str = Convert.ToString(Convert.ToInt64(str, 16), 2);
            if (str.Length < 8)
                str = new string('0', 8 - str.Length) + str;
            return str;
        }
        public static string To_Hexa(string str)
        {
            //convert from Binary to Hexa
            string res = "";
            string test = "";
            for (int i = 0; i < str.Length; i += 4)
            {
                if (i < str.Length && i + 1 < str.Length && i + 2 < str.Length && i + 3 < str.Length)
                {
                    res = str[i].ToString() + str[i + 1].ToString() + str[i + 2].ToString() + str[i + 3].ToString();
                    res = Convert.ToInt32(res, 2).ToString();

                }
                if (res.Length != 1)
                {
                    if (res == "10")
                        res = "A";
                    else if (res == "11")
                        res = "B";
                    else if (res == "12")
                        res = "C";
                    else if (res == "13")
                        res = "D";
                    else if (res == "14")
                        res = "E";
                    else
                        res = "F";
                }
           
                test = test + res;
            }
            //res = Convert.ToString(Convert.ToInt64(str, 16), 2);
            return test;
        }
        public static string RoundKey(string str1, string str2)
        {
            string result = "";
            for (int i = 0; i < str2.Length; i++)
            {
                if (i < str1.Length && str1[i] == str2[i])
                    result += '0';
                else
                    result += '1';
            }
            return result;
        }
        public static int whereBox(string a)
        {
            int res = 0;
            if (a.Length == 2)
            {
                int char1 = Convert.ToInt32(a[0].ToString(), 16);
                int char2 = Convert.ToInt32(a[1].ToString(), 16);
                res = char1 * 16 + char2;
            }

            return res;
        }

        /**********************************************************************************/

        byte[,] sbox = new byte[16, 16] {   {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };
        static byte[,] sboxInverse = new byte[16, 16] { { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
                                                        { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
                                                        { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
                                                        { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
                                                        { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
                                                        { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
                                                        { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
                                                        { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
                                                        { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
                                                        { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
                                                        { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
                                                        { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
                                                        { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
                                                        { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
                                                        { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
                                                        { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };
        int index = 0;
        byte[,] key_rounds = new byte[44, 4];
        byte[,] Rcon2 = new byte[4, 10] { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
        byte[,] galoisFieldInverse = new byte[4, 4] {   {0x0e, 0x0b, 0x0d, 0x09},
                                                        {0x09, 0x0e, 0x0b, 0x0d},
                                                        {0x0d, 0x09, 0x0e, 0x0b},
                                                        {0x0b, 0x0d, 0x09, 0x0e}};

        byte[] rolate_word(byte[] word)
        {
            byte first = word[0];
            for (int i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = first;
            return word;
        }
        byte[] Sub_Byte(byte[] word)
        {
            byte[] res = new byte[4];
            int II;
            int JJ;
            int i = 0;
            while (i < 4)
            {
                string tmp = Convert.ToString(word[i], 16);
                if (tmp.Length != 1)
                {

                    II = Convert.ToInt32(tmp[0].ToString(), 16);
                    JJ = Convert.ToInt32(tmp[1].ToString(), 16);
                }
                else
                {
                    II = 0;
                    JJ = Convert.ToInt32(tmp[0].ToString(), 16);
                }
                res[i] = sbox[II, JJ];
                i++;
            }
            return res;
        }
        byte[] xor(byte[] first, byte[] second, byte[] third, int multiple_4)
        {
            byte[] result = new byte[4];
            int i = 0;
            while (i < 4)
            {
                string tmp;
                if (multiple_4 == 0)
                {
                    tmp = Convert.ToString(first[i] ^ second[i], 16);
                }
                else
                {
                    tmp = Convert.ToString(first[i] ^ second[i] ^ third[i], 16);
                }
                result[i] = Convert.ToByte(tmp, 16);
                i++;
            }
            return result;
        }
        string make_string_matrix(byte[,] matrix)
        {
            StringBuilder tmp = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                int j = 0;
                while (j < 4)
                {
                    var temp = Convert.ToString(matrix[j, i], 16);
                    if (temp.Length <= 1)
                    {
                        tmp.Append("0" + temp);
                    }
                    else
                    {
                        tmp.Append(temp);
                    }
                    j++;
                }
            }
            return tmp.ToString().ToUpper().Insert(0, "0x");
        }
        byte[,] create_Byte_Matrix(string x)
        {
            byte[,] matrix = new byte[4, 4];
            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + x[k] + x[k + 1];
                    matrix[i, j] = Convert.ToByte(tmp, 16);
                    k += 2;
                }
            }
            return matrix;
        }
        byte[,] ByteMatrix2(string x)
        {
            byte[,] new_matrix = new byte[4, 4];

            int cell = 2;
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    string tmp = "0x" + x[cell] + x[cell + 1];
                    new_matrix[row, col] = Convert.ToByte(tmp, 16);
                    cell += 2;
                }
            }
            return new_matrix;
        }
        void insert_key(string key)
        {
            byte[,] arr = new byte[4, 4];
            arr = ByteMatrix2(key);
            int i = 0;
            while (i < 4)
            {
                for (int j = 0; j < 4; j++)
                {
                    key_rounds[i, j] = arr[i, j];
                }
                i++;
            }
        }
        byte[,] get_key_matrix(int index)
        {
            byte[,] matrix = new byte[4, 4];
            int row = 0, col = 0;
            int i = index * 4;
            while (i < index * 4 + 4)
            {
                col = 0;
                for (int j = 0; j < 4; j++)
                {
                    matrix[col, row] = key_rounds[i, j];
                    col++;
                }
                row++;
                i++;
            }
            return matrix;
        }
        byte[,] RoundKey(byte[,] matrix, int round_index)
        {
            byte[,] key;
            key = get_key_matrix(round_index);

            dis_matrix(key);

            dis_matrix(matrix);

            string empty;
            int i = 0;
            while (i < 4)
            {
                for (int j = 0; j < 4; j++)
                {
                    empty = Convert.ToString(key[i, j] ^ matrix[i, j], 16);
                    key[i, j] = Convert.ToByte(empty, 16);
                }
                i++;
            }
            return key;
        }
        void implement_key_expansion()
        {
            byte[] first = new byte[4];
            byte[] second = new byte[4];
            byte[] third = new byte[4];
            byte[] fourth = new byte[4];
            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    second[j] = key_rounds[i - 4, j];
                    first[j] = key_rounds[i - 1, j];

                    if (index < 10)
                    {
                        third[j] = Rcon2[j, index];
                    }
                }
                if (i % 4 != 0)
                {
                    fourth = xor(first, second, third, 0);
                }
                else
                {
                    index++;
                    first = rolate_word(first);
                    first = Sub_Byte(first);
                    fourth = xor(first, second, third, 1);


                }
                for (int j = 0; j < 4; j++)
                {
                    key_rounds[i, j] = fourth[j];
                }

            }
        }
        void dis_matrix(byte[,] mat)
        {
            int i = 0;
            int j = 0;
            while (i < 4)
            {
                while (j < 4)
                {
                    Console.Write(string.Join(", ", mat[i, j].ToString("X2")));
                    Console.Write(" ");
                    j++;
                }
                Console.WriteLine();
                i++;
            }

            Console.WriteLine("");
        }
        byte multiply_by_Two(byte x)
        {
            byte result;
            UInt32 emp = Convert.ToUInt32(x << 1);
            result = (byte)(emp & 0xFF);
            if (x > 127)
            {
                result = Convert.ToByte(result ^ 27);
            }
            return result;
        }
        byte[,] mix_Coloums_Inver(byte[,] shiftedmatrix)
        {
            List<byte> mix_matrix = new List<byte>();
            byte[] xor_arr = new byte[4];
            byte[,] mix_Coloums_Matrix = new byte[4, 4];
            int i = 0;
            while (i < 4)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galoisFieldInverse[j, k] == 0x9)
                        {
                            byte first = shiftedmatrix[k, i];
                            byte second = multiply_by_Two(first);
                            byte third = multiply_by_Two(second);
                            byte fourth = multiply_by_Two(third);
                            xor_arr[k] = Convert.ToByte(fourth ^ first);
                        }
                        if (galoisFieldInverse[j, k] == 0xB)
                        {
                            byte first = shiftedmatrix[k, i];
                            byte second = multiply_by_Two(first);
                            byte third = multiply_by_Two(second);
                            byte fourth = multiply_by_Two(third);
                            xor_arr[k] = Convert.ToByte(fourth ^ first ^ second);
                        }
                        if (galoisFieldInverse[j, k] == 0xD)
                        {
                            byte first = shiftedmatrix[k, i];
                            byte second = multiply_by_Two(first);
                            byte third = multiply_by_Two(second);
                            byte fourth = multiply_by_Two(third);
                            xor_arr[k] = Convert.ToByte(fourth ^ third ^ first);


                        }

                        if (galoisFieldInverse[j, k] == 0xE)
                        {
                            byte first = shiftedmatrix[k, i];
                            byte second = multiply_by_Two(first);
                            byte third = multiply_by_Two(second);
                            byte fourth = multiply_by_Two(third);
                            xor_arr[k] = Convert.ToByte(fourth ^ third ^ second);
                        }
                    }
                    var final = xor_arr[0] ^ xor_arr[1] ^ xor_arr[2] ^ xor_arr[3];
                    mix_Coloums_Matrix[j, i] = Convert.ToByte(final);
                }
                i++;
            }
            return mix_Coloums_Matrix;
        }
        byte[,] sub_mat_Inver(byte[,] matrix)
        {
            byte[,] emp_matrix = new byte[4, 4];
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string empty = Convert.ToString(matrix[i, j], 16);
                    int II, JJ;
                    if (empty.Length != 1)
                    {

                        II = Convert.ToInt32(empty[0].ToString(), 16);
                        JJ = Convert.ToInt32(empty[1].ToString(), 16);
                    }
                    else
                    {
                        II = 0;
                        JJ = Convert.ToInt32(empty[0].ToString(), 16);

                    }
                    emp_matrix[i, j] = sboxInverse[II, JJ];
                    j++;
                }
                i++;
            }
            return emp_matrix;
        }
        byte[] shifts_row_inver(byte[] row, int n)
        {
            int kk = 0;
            UInt32 num_assist = 0;
            while (kk < 4)
            {
                num_assist += Convert.ToUInt32(row[kk]);
                if (kk != 3)
                {
                    num_assist = num_assist << 8;
                }
                kk++;
            }
            num_assist = ((num_assist >> (n * 8)) | (num_assist) << (32 - (n * 8)));
            byte[] new_rows = new byte[4];
            int i = 3;
            while (i >= 0)
            {
                new_rows[i] = (byte)(num_assist & 0xFF);
                num_assist = num_assist >> 8;
                i--;
            }
            return new_rows;
        }
        byte[,] shift_mat_Inver(byte[,] matrix)
        {
            byte[,] emp_matrix = new byte[4, 4];
            byte[] row = new byte[4];
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                int ll = 0;
                while (j < 4)
                {
                    row[j] = matrix[i, j];
                    j++;
                }
                row = shifts_row_inver(row, i);
                while (ll < 4)
                {
                    emp_matrix[i, ll] = row[ll];
                    ll++;
                }
                i++;
            }
            return emp_matrix;
        }
        byte[,] last_Round_Decry(byte[,] state)
        {
            state = RoundKey(state, 10);
            dis_matrix(state);

            state = shift_mat_Inver(state);
            dis_matrix(state);

            state = sub_mat_Inver(state);
            dis_matrix(state);

            return state;
        }
        byte[,] mains_rounds_decry(byte[,] plian_text, int round)
        {
            plian_text = RoundKey(plian_text, round);
            dis_matrix(plian_text);
            plian_text = mix_Coloums_Inver(plian_text);
            dis_matrix(plian_text);
            plian_text = shift_mat_Inver(plian_text);
            dis_matrix(plian_text);
            plian_text = sub_mat_Inver(plian_text);
            dis_matrix(plian_text);
            return plian_text;
        }
        byte[,] first_Round_Decry(byte[,] state)
        {
            state = RoundKey(state, 0);
            return state;
        }

        /*********************************************************************************/

        public override string Decrypt(string cipherText, string key)
        {
            byte[,] plan_text = create_Byte_Matrix(cipherText);
            insert_key(key);
            implement_key_expansion();
            plan_text = last_Round_Decry(plan_text);
            dis_matrix(plan_text);

            for (int i = 9; i > 0; i--)
            {
                plan_text = mains_rounds_decry(plan_text, i);
            }

            plan_text = first_Round_Decry(plan_text);
            dis_matrix(plan_text);
            return make_string_matrix(plan_text);
        }

        public override string Encrypt(string plainText, string key)
        {
            string cipherText = "0x";
            string[,] plainText_matrix = Generate_Matrix(plainText);
            string[,] key_matrix = Generate_Matrix(key);
            string[,] plainText_Binary = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainText_Binary[i, j] = To_Binary(plainText_matrix[i, j]);
                }
            }

            int r = 0;
            int cou = 0;
            int count = 0;
            int counter = 0;
            string roundMat = "";
            string roundMat1 = "";
            string totalStr1 = "";
            string totalStr2 = "";
            string totalSt = "";
            string[,] matFainal = new string[4, 4];
            string[,] colMatrix = new string[4, 1];
            string[,] rconMatrix = new string[4, 1];
            string[,] rcon = new string[4, 10];
            string[,] lastCol = new string[4, 1];
            string[,] Key_Binary = new string[4, 4];
            string[,] stateRounded = new string[4, 4];
            string[,] totalColMatrix = new string[4, 1];
            string[,] sBoxMatrixChanger = new string[4, 4];


            //round key1
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Key_Binary[i, j] = To_Binary(key_matrix[i, j]);
                    stateRounded[i, j] = RoundKey(Key_Binary[i, j], plainText_Binary[i, j]);
                    stateRounded[i, j] = (To_Hexa(stateRounded[i, j])).ToString();

                }
            }

            for (int i = 0; i < 9; i++)
            {
                //SubBytes

                for (int j = 0; j < 4; j++)
                    for (int q = 0; q < 4; q++)
                        sBoxMatrixChanger[j, q] = SBOX[whereBox(stateRounded[j, q])];

                // Shift Rows
                sBoxMatrixChanger = Shift_Rows(sBoxMatrixChanger);

                //Mix Columns
                counter = 0;
                int col = 0;
                string[,] maxCol = new string[4, 4];
                string[,] sBoxMatrixChangerBinary = new string[4, 4];

                for (int o = 0; o < 4; o++)
                    for (int j = 0; j < 4; j++)
                        sBoxMatrixChangerBinary[o, j] = To_Binary(sBoxMatrixChanger[o, j]);

                //Multiplying two matrices of hexa numbers
                for (int j = 0; j < 4; j++)
                {
                    counter = 0;

                    for (int q = 0; q < 4; q++)
                    {
                        for (int w = 0; w < 4; w += 2)
                        {
                            totalStr2 = totalStr1;

                            if (counter < mixCols.Length && w + 1 < 4 && counter + 1 < mixCols.Length)
                            {
                                string str1 = sBoxMatrixChangerBinary[w, j];
                                string str2 = sBoxMatrixChangerBinary[w + 1, j];


                                string mixCol = mixCols[counter];
                                string mixCol1 = mixCols[counter + 1];
                                counter += 2;

                                if (mixCol == "02")
                                {
                                    str1 = EditMatrixBinaryShift(str1);

                                    if (str1[7].Equals('1'))
                                    {
                                        str1 = str1.Remove(7, 1);
                                        str1 = str1.Insert(7, "0");

                                        string st = "00011011";
                                        str1 = RoundKey(str1, st);

                                    }
                                }

                                if (mixCol1 == "02")
                                {
                                    str2 = EditMatrixBinaryShift(str2);
                                    if (str2[7].Equals('1'))
                                    {
                                        str2 = str2.Remove(7, 1);
                                        str2 = str2.Insert(7, "0");
                                        string st = "00011011";
                                        str2 = RoundKey(str2, st);
                                    }
                                }

                                if (mixCol == "03")
                                {
                                    string editStr1 = "";
                                    // once "01"
                                    editStr1 = str1;
                                    // once "02"
                                    str1 = EditMatrixBinaryShift(str1);
                                    if (str1[7].Equals('1'))
                                    {
                                        str1 = str1.Remove(7, 1);
                                        str1 = str1.Insert(7, "0");
                                        string st = "00011011";
                                        str1 = RoundKey(str1, st);
                                    }

                                    str1 = RoundKey(str1, editStr1);
                                }

                                if (mixCol1 == "03")
                                {
                                    string editStr2 = "";
                                    editStr2 = str2;
                                    str2 = EditMatrixBinaryShift(str2);
                                    if (str2[7].Equals('1'))
                                    {
                                        str2 = str2.Remove(7, 1);
                                        str2 = str2.Insert(7, "0");
                                        string st = "00011011";
                                        str2 = RoundKey(str2, st);
                                    }

                                    str2 = RoundKey(str2, editStr2);
                                }

                                totalStr1 = RoundKey(str1, str2);

                            }

                            totalSt = RoundKey(totalStr1, totalStr2);

                        }
                        if (col < 4)
                            maxCol[q, col] = To_Hexa(totalSt);
                    }
                    col++;

                }

                //AddRooundKey
                for (int p = 0; p < 4; p++)
                    lastCol[p, 0] = key_matrix[p, 3];

                lastCol = EditLastColumn(lastCol);
                for (int p = 0; p < 4; p++)
                    lastCol[p, 0] = SBOX[whereBox(lastCol[p, 0])];

                // full Matrix Rcon
                for (int p = 0; p < 4; p++)
                {
                    for (int w = 0; w < 10; w++)
                    {
                        if (count < Rcon.Length)
                        {
                            rcon[p, w] = Rcon[count];
                            count++;
                        }
                    }
                }


                r = 0;
                for (int p = 0; p < 4; p++)
                {
                    if (cou < 10)
                    {
                        colMatrix[p, 0] = key_matrix[p, 0];
                        rconMatrix[p, 0] = rcon[p, cou];
                    }

                }

                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binaryLastCol = To_Binary(lastCol[p, 0]);
                    string binaryRconMatrix = To_Binary(rconMatrix[p, 0]);
                    roundMat = RoundKey(binaryColMatrix, binaryLastCol);
                    roundMat1 = RoundKey(roundMat, binaryRconMatrix);
                    key_matrix[p, r] = To_Hexa(roundMat1);
                }
                r = 1;
                for (int p = 0; p < 4; p++)
                    colMatrix[p, 0] = key_matrix[p, r];
                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binarylastCol = To_Binary(key_matrix[p, 0]);
                    roundMat = RoundKey(binaryColMatrix, binarylastCol);
                    key_matrix[p, r] = To_Hexa(roundMat);

                }

                r = 2;
                for (int p = 0; p < 4; p++)
                    colMatrix[p, 0] = key_matrix[p, 2];
                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binarylastCol = To_Binary(key_matrix[p, 1]);
                    roundMat = RoundKey(binaryColMatrix, binarylastCol);
                    key_matrix[p, r] = To_Hexa(roundMat);

                }

                r = 3;
                for (int p = 0; p < 4; p++)
                    colMatrix[p, 0] = key_matrix[p, r];
                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binarylastCol = To_Binary(key_matrix[p, 2]);
                    roundMat = RoundKey(binaryColMatrix, binarylastCol);
                    key_matrix[p, r] = To_Hexa(roundMat);

                }

                //round key
                for (int g = 0; g < 4; g++)
                {
                    for (int e = 0; e < 4; e++)
                    {
                        string s1 = To_Binary(maxCol[e, g]);
                        string s2 = To_Binary(key_matrix[e, g]);
                        string totalS = RoundKey(s1, s2);
                        stateRounded[e, g] = To_Hexa(totalS);

                    }
                }

                cou++;

            }

            //SubBytes

            for (int j = 0; j < 4; j++)
                for (int q = 0; q < 4; q++)
                    sBoxMatrixChanger[j, q] = SBOX[whereBox(stateRounded[j, q])];

            // Shift Rows
            sBoxMatrixChanger = Shift_Rows(sBoxMatrixChanger);

            //AddRooundKey
            for (int p = 0; p < 4; p++)
                lastCol[p, 0] = key_matrix[p, 3];

            lastCol = EditLastColumn(lastCol);
            for (int p = 0; p < 4; p++)
                lastCol[p, 0] = SBOX[whereBox(lastCol[p, 0])];

            // full Matrix Rcon
            count = 0;
            for (int p = 0; p < 4; p++)
            {
                for (int w = 0; w < 10; w++)
                {
                    if (count < Rcon.Length)
                    {
                        rcon[p, w] = Rcon[count];
                        count++;
                    }
                }
            }

            //Multiplying two matrices of hexa numbers
            r = 0;
            for (int p = 0; p < 4; p++)
            {
                colMatrix[p, 0] = key_matrix[p, 0];
                rconMatrix[p, 0] = rcon[p, 9];
            }

            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binaryLastCol = To_Binary(lastCol[p, 0]);
                string binaryRconMatrix = To_Binary(rconMatrix[p, 0]);
                roundMat = RoundKey(binaryColMatrix, binaryLastCol);
                roundMat1 = RoundKey(roundMat, binaryRconMatrix);
                key_matrix[p, r] = To_Hexa(roundMat1);
            }
            r = 1;
            for (int p = 0; p < 4; p++)
                colMatrix[p, 0] = key_matrix[p, r];
            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binarylastCol = To_Binary(key_matrix[p, 0]);
                roundMat = RoundKey(binaryColMatrix, binarylastCol);
                key_matrix[p, r] = To_Hexa(roundMat);

            }

            r = 2;
            for (int p = 0; p < 4; p++)
                colMatrix[p, 0] = key_matrix[p, 2];
            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binarylastCol = To_Binary(key_matrix[p, 1]);
                roundMat = RoundKey(binaryColMatrix, binarylastCol);
                key_matrix[p, r] = To_Hexa(roundMat);

            }

            r = 3;
            for (int p = 0; p < 4; p++)
                colMatrix[p, 0] = key_matrix[p, r];
            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binarylastCol = To_Binary(key_matrix[p, 2]);
                roundMat = RoundKey(binaryColMatrix, binarylastCol);
                key_matrix[p, r] = To_Hexa(roundMat);

            }

            //round key
            for (int g = 0; g < 4; g++)
            {
                for (int e = 0; e < 4; e++)
                {
                    string s1 = To_Binary(sBoxMatrixChanger[e, g]);
                    string s2 = To_Binary(key_matrix[e, g]);
                    string totalS = RoundKey(s1, s2);
                    stateRounded[e, g] = To_Hexa(totalS);

                }
            }

            for (int g = 0; g < 4; g++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherText += stateRounded[j, g];
                }
            }

            return cipherText;
        }
    }
}
