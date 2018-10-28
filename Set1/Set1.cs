using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;



namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            string thisFile = File.ReadAllText(@"FILE LOCATION");
            var testVar = challenge8();
            Console.WriteLine(testVar);
            Console.ReadKey();
        }

        ///<summary>
        ///Takes a hex string and converts it to a bytes, returns a byte array
        ///</summary>
        public static byte[] hex2Bytes(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        ///<summary>
        ///Takes a hex string and converts it to base 64, returns a base64 string
        ///</summary>
        public static string challenge1(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            String base64 = Convert.ToBase64String(bytes);
            return base64;
        }

        ///<summary>
        ///Takes 2 equal length hex strings, Xor's them together and returns the result.
        ///</summary>
        public static string challenge2(string buffer1, string buffer2)
        {
            //Pass each buffer to hex2Bytes to convert a hex string into a byte array
            byte[] byteBuffer1 = hex2Bytes(buffer1);
            byte[] byteBuffer2 = hex2Bytes(buffer2);

            int bufferSize = byteBuffer1.Length;
            byte[] xoredBuffer = new byte[bufferSize];
            string result = "";

            //Confirm each byte array is of equal length, exit the funtion if they aren't
            if (byteBuffer1.Length != byteBuffer2.Length)
            {
                return "ERROR BUFFERS NOT EQUAL!";
            }

            //Iterates over each byte array bit by bit and Xor's them together, sorting the result in xoredBuffer
            for (int a = 0; a < bufferSize; a++)
            {
                xoredBuffer[a] = (byte)(byteBuffer1[a] ^ byteBuffer2[a]);
            }

            //Converts the byte array back to a hex string and drops the "-" characters
            result = BitConverter.ToString(xoredBuffer).Replace("-", string.Empty);

            return result;
        }

        ///<summary>
        ///Takes a single byte xor encrypted string and returns the result most likely to be human readable
        ///</summary>
        public static (string, char) challenge4(List<string> bufferList)
        {
            //Create some variables to hold our restults
            int humanReadableScore = 0;
            string humanReadableString = "";
            char xorKey = ' ';

            //This is every character we will be testing against the cipher text.
            const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 ";

            foreach (string buffer in bufferList){
                //Decode our hex encoded string
                byte[] cipherByteBuffer = hex2Bytes(buffer);
                byte[] plainByteBuffer = new byte[cipherByteBuffer.Length];

                //Go through each character in our list
                for(int a = 0; a < characters.Length; a++)
                {
                    //Go through each byte in the array
                    for (int b = 0; b < cipherByteBuffer.Length; b++)
                    {
                        //Xor the current character against the current byte
                        plainByteBuffer[b] = (byte)(cipherByteBuffer[b] ^ characters[a]);
                    }

                    //Change the xor result back to a string
                    string plainText = Encoding.Default.GetString(plainByteBuffer);

                    //Declare some variables to store results in as we move through the string
                    char currentChar = '%';
                    char prevChar = '%';
                    char nextChar = '%';
                    int score = 0;
          
                    //Iterate over the string
                    for(int b = 1; b < plainText.Length - 1; b++)
                    {
                        currentChar = plainText[b];
                        prevChar = plainText[b - 1];
                        nextChar = plainText[b + 1];

                        //Check if the current character is a space, not followed or proceeded by another space
                        if (currentChar == ' ') //&& prevChar != ' ' && nextChar != ' ')
                        {
                            score++;
                        }
                    }

                    //Update results as better results are found.
                    if(score > humanReadableScore)
                    {
                        humanReadableScore = score;
                        humanReadableString = plainText;
                        xorKey = characters[a];
                    }
                } 
            }

            Console.WriteLine("Score: {0}\nText: {1}\nKey: {2}", humanReadableScore, humanReadableString, xorKey);
            return (humanReadableString, xorKey);
        }

        ///<summary>
        ///Takes a string and a key, XOR's the pair, hex encodes and returns the result as a string.
        ///</summary>
        public static string challenge5(string buffer, string key)
        {
            int keyIterator = 0;
            byte[] byteBuffer = Encoding.Default.GetBytes(buffer);
            byte[] xoredBytes = new byte[byteBuffer.Length];

            for (int a = 0; a < byteBuffer.Length; a++)
            {
                if (keyIterator >= key.Length)
                {
                    keyIterator = 0;
                }

                xoredBytes[a] = (byte)(byteBuffer[a] ^ key[keyIterator]);
                keyIterator++;
            }

            string text = Encoding.Default.GetString(xoredBytes);
            String base64 = BitConverter.ToString(xoredBytes).Replace("-", string.Empty);
            return text;
        }

        ///<summary>
        ///Takes a base64 encoded text, returns it to a string, identifies a repeating key xor and decrypts it and returns the plain text as a string.
        ///</summary>
        public static string challenge6(string base64Text)
        {
            byte[] cipherBytes = Convert.FromBase64String(base64Text);
            decimal[] keySizes = keySpaceCalc(cipherBytes);
            List<string> keys = new List<string>();
            List<string> plainText = new List<string>();

            foreach (decimal keySize in keySizes)
            {
                var encodedBytes = byteSplitter(cipherBytes, (int)keySize);
                string key = "";
                for (int a = 0; a < encodedBytes.Count; a++)
                {
                    key += singleByteXor(encodedBytes[a]);
                }
                keys.Add(key);
            }

            foreach(string key in keys)
            {
                string text = repeatingKeyXorEncode(cipherBytes, key);
                plainText.Add(text);
            }

            int successChance = 0;
            string decrypted = "";
            foreach (string text in plainText)
            {
                int success = 0;
                for (int a = 1; a < text.Length - 1; a++)
                {
                    char prevChar = text[a - 1];
                    char currentChar = text[a];
                    char nextChar = text[a + 1];
                    if (currentChar == '\n' && prevChar != '\n' && char.IsUpper(nextChar))
                    { 
                        success++;
                    }
                }

                if(success > successChance)
                {
                    decrypted = text;
                }
            }

            Console.WriteLine(decrypted);
            return "";
        }

        //All functions from here on down are modified to complete the breakReapeatingXor func.

        public static string repeatingKeyXorEncode(byte[] byteBuffer, string key)
        {
            int keyIterator = 0;
            byte[] xoredBytes = new byte[byteBuffer.Length];

            for (int a = 0; a < byteBuffer.Length; a++)
            {
                if (keyIterator >= key.Length)
                {
                    keyIterator = 0;
                }

                xoredBytes[a] = (byte)(byteBuffer[a] ^ key[keyIterator]);
                keyIterator++;
            }

            string text = Encoding.Default.GetString(xoredBytes);
            return text;
        }

        public static char singleByteXor(byte[] cipherByteBuffer)
        {
            //Create some variables to hold our restults
            int humanReadableScore = 0;
            string humanReadableString = "";
            char xorKey = ' ';
            //This is every character we will be testing against the cipher text.
            const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 ";

            //Decode our hex encoded string
            //byte[] cipherByteBuffer = hex2Bytes(buffer);
            byte[] plainByteBuffer = new byte[cipherByteBuffer.Length];

            //Go through each character in our list
            for (int a = 0; a < characters.Length; a++)
            {
                //Go through each byte in the array
                for (int b = 0; b < cipherByteBuffer.Length; b++)
                {
                    //Xor the current character against the current byte
                    if(cipherByteBuffer[b] == 0)
                    {
                        //Console.WriteLine("cipherByteBuffer (within if) = {0}", cipherByteBuffer[b]);
                        continue;
                    }
                    //Console.WriteLine("cipherByteBuffer = {0}", cipherByteBuffer[b]);
                    plainByteBuffer[b] = (byte)(cipherByteBuffer[b] ^ characters[a]);
                }

                //Change the xor result back to a string
                string plainText = Encoding.Default.GetString(plainByteBuffer);

                //Declare some variables to store results in as we move through the string
                char currentChar = '%';
                char prevChar = '%';
                char nextChar = '%';
                int score = 0;

                //Iterate over the string
                for (int b = 1; b < plainText.Length - 1; b++)
                {
                    currentChar = plainText[b];
                    prevChar = plainText[b - 1];
                    nextChar = plainText[b + 1];

                    //Check if the current character is a space, not followed or proceeded by another space
                    if (currentChar == ' ' || currentChar == 'e' || currentChar == 'a') //&& prevChar != ' ' && nextChar != ' ')
                    {
                        score++;
                    }
                }

                //Update results as better results are found.
                if (score > humanReadableScore)
                {
                    humanReadableScore = score;
                    humanReadableString = plainText;
                    xorKey = characters[a];
                }
            }
            return xorKey;
        }

        ///<summary>
        ///Takes a byte array and breaks it down into X byte arrays, returns as a list of byte arrays.
        ///Breaks byte arrays into key spaces, i.e. every 1st byte will be one section, every 2nd byte another.
        ///</summary>
        public static List<byte[]> byteSplitter(byte[] bytes, int keySize)
        {
            List<byte[]> cipherKeySpaces = new List<byte[]>();
            for (int a = 0; a < keySize; a++)
            {
                List<byte> tempByte = new List<byte>();
                int loopCounter = 0;
                for (int b = 0; b < bytes.Length; b++)
                {
                    if (loopCounter == a)
                    {
                         tempByte.Add(bytes[b]);
                    }

                    loopCounter++;

                    if (loopCounter >= keySize)
                    {
                        loopCounter = 0;
                    }
                }
                cipherKeySpaces.Add(tempByte.ToArray());
            }
            return cipherKeySpaces;
        }

        ///<summary>
        ///Takes a cipher text as a byte array and works out the most likely key length used when XORing, returns key length as int
        ///</summary>
        public static decimal[] keySpaceCalc(byte[] cipherBytes)
        {
            decimal[] keySpace = new decimal[5];
            keySpace[0] = 1000;
            decimal[] keySize = new decimal[5];
            
            for (int a = 40; a >= 2; a--)
            {
                byte[] keySpace1 = new byte[a];
                for (int b = 0; b < a; b++)
                {
                    keySpace1[b] = cipherBytes[b];
                }

                byte[] keySpace2 = new byte[a];
                for (int b = 0; b < a; b++)
                {
                    keySpace2[b] = cipherBytes[a + b];
                }

                byte[] keySpace3 = new byte[a];
                for (int b = 0; b < a; b++)
                {
                    keySpace3[b] = cipherBytes[(a * 2) + b];
                }

                byte[] keySpace4 = new byte[a];
                for (int b = 0; b < a; b++)
                {
                    keySpace4[b] = cipherBytes[(a * 3) + b];
                }
              
                int edit1 = editDistanceCalc(keySpace1, keySpace2);
                int edit2 = editDistanceCalc(keySpace3, keySpace4);

                decimal edit = ((((decimal)edit1 + edit2) / 2) / a);

                //Get top 5 most likely key sizes.
                if(edit < keySpace[0] && edit > 0)
                {
                    keySpace[4] = keySpace[3];
                    keySize[4] = keySize[3];
                    keySpace[3] = keySpace[2];
                    keySize[3] = keySize[2];
                    keySpace[2] = keySpace[1];
                    keySize[2] = keySize[1];
                    keySpace[1] = keySpace[0];
                    keySize[1] = keySize[0];
                    keySpace[0] = edit;
                    keySize[0] = a;
                }
            }
            return keySize;
        }

        ///<summary>
        ///Takes 2 byte arrays and returns the edit distance between the two as an int.
        ///</summary>
        public static int editDistanceCalc(byte[] bytes1, byte[] bytes2)
        {
            int editDistance = 0;
           
            BitArray BA1 = new BitArray(bytes1);
            BitArray BA2 = new BitArray(bytes2);
           
            for (int a = 0; a < BA1.Length; a++)
            {
                if (BA1[a] != BA2[a])
                {
                    editDistance++;
                }
            }

            return editDistance;
        }

        public static string challenge7(string thisFile, string key)
        {
            var a = new AesManaged();
            a.Key = Encoding.ASCII.GetBytes(key);
            a.Mode = CipherMode.ECB;

            var base64 = thisFile;
            byte[] bytes = Convert.FromBase64String(base64);

            var decryptor = a.CreateDecryptor();

            byte[] result = decryptor.TransformFinalBlock(bytes, 0, bytes.Length);
            string text = Encoding.UTF8.GetString(result);
            return text;
        }

        public static string challenge8()
        {
            string ecbString = "";
            foreach (string line in File.ReadLines(@"FILE LOCATION"))
            {
                int loopCounter = 0;
                int innerLoopCounter = 0;
                int repeats = 0;
                byte[] bytes = hex2Bytes(line);
                byte[] byteCurrent = new byte[16];
                foreach(byte b in bytes)
                {
                    if(loopCounter > 15)
                    {
                        loopCounter = 0;
                        byte[] testByte = new byte[16];
                        foreach(byte byt in bytes)
                        {
                            if(innerLoopCounter > 15)
                            {
                                innerLoopCounter = 0;
                                if(StructuralComparisons.StructuralEqualityComparer.Equals(testByte, byteCurrent))
                                {
                                    repeats++;
                                }
                            }
                            testByte[innerLoopCounter] = byt;
                            innerLoopCounter++;
                        }
                        if(repeats > 1)
                        {
                            ecbString = line;
                        }
                        repeats = 0;
                    }
                    byteCurrent[loopCounter] = b;
                    loopCounter++;
                }
            }
            Console.WriteLine("ECBString = {0}", ecbString);
            return ecbString;
        }
    }
}
