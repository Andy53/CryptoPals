using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CryptoLib;

namespace cryptoPalsSet2
{
    partial class Program
    {
        static string challenge12()
        {
            //Plaintext versions of values to be encrypted
            string secretKeyPlain = "BBBBBBBBBBBBBBBB";
            string knownText      = "AAAAAAAAAAAAAAA";
            string cipherText     = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByY" +
                                    "WctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYm" +
                                    "xvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHd" +
                                    "hdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91" +
                                    "IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

            //Values once converted to bytes
            byte[] knownBytes     = Encoding.ASCII.GetBytes(knownText);
            byte[] cipherBytes    = Convert.FromBase64String(cipherText);
            byte[] keyBytes       = Encoding.ASCII.GetBytes(secretKeyPlain);
            byte[] decryptedBytes = new byte[cipherText.Length];

            int blockSize = IdentifyBlockSize(keyBytes);
            string final = decryptor(knownBytes, cipherBytes, keyBytes, blockSize);
            Console.WriteLine(final);
            return "";
        }

        public static string decryptor(byte[] knownBytes, 
            byte[] encryptedBytes, byte[] key, int blockSize)
        {
            byte[] data = new byte[knownBytes.Length + encryptedBytes.Length];
            
            Array.Copy(knownBytes, 0, data, 0, knownBytes.Length);
            Array.Copy(encryptedBytes, 0, data, knownBytes.Length, encryptedBytes.Length);

            Dictionary<int, byte[]> dict = new Dictionary<int, byte[]>();
            List<int> decrypted = new List<int>();

            byte[] block = new byte[blockSize];
            for(int a = 0; a < blockSize - 1; a++)
            {
                block[a] = (byte)'A';
            }

            //Iterate through encrypted data
            for (int a = blockSize - 1; a < data.Length - blockSize; a++)
            {
                for (int b = 0; b < blockSize; b++)
                {
                    block[b] = data[a + b];
                }
                dict = populateDict(block, key, blockSize);
                byte[] encBlock = CryptoHelpers.EcbEncrypt(block, key);
                foreach (var v in dict)
                {
                    if (encBlock.SequenceEqual(v.Value))
                    {
                        decrypted.Add(v.Key);
                    }
                }
            }

            string final = "";
            foreach(char c in decrypted)
            {
                final += c;
            }

            return final;
        }

        public static Dictionary<int, byte[]> populateDict(byte[] data, 
            byte[] key, int blocksize)
        {
            Dictionary<int, byte[]> decodedByteDict = new Dictionary<int, byte[]>();

            for (int a = 0; a < 255; a++)
            {
                byte[] block = new byte[blocksize];
                Array.Copy(data, 0, block, 0, data.Length);
                block[blocksize - 1] = (byte)a;
                decodedByteDict.Add(a, CryptoHelpers.EcbEncrypt(block, key));
            }
            return decodedByteDict;
        }


        public static int IdentifyBlockSize(byte[] key)
        {
            int keySize = 0;
            string plainText = "";
            for (int a = 0; a < 10000; a++)
            {
                plainText += "A";
            }
            byte[] data = Encoding.ASCII.GetBytes(plainText);
            byte[] encryptedData = CryptoHelpers.EcbEncrypt(data, key);

            for (int a = 1; a < encryptedData.Length / 2; a++)
            {
                byte[] repeat = new byte[a];
                for (int b = 0; b < repeat.Length; b++)
                {
                    repeat[b] = encryptedData[b];
                }

                byte[] currentBlock = new byte[a];
                for (int b = a; b < a + repeat.Length; b++)
                {
                    currentBlock[b - a] = encryptedData[b];
                }

                if (currentBlock.SequenceEqual(repeat))
                {
                    byte[] nextBlock = new byte[a];
                    for (int b = a * 2; b < a * 2 + repeat.Length; b++)
                    {
                        nextBlock[b - (a * 2)] = encryptedData[b];
                    }
                    if (nextBlock.SequenceEqual(repeat))
                    {
                        keySize = a;
                        return keySize;
                    }
                }
            }
            return -1;
        }
    }
}
