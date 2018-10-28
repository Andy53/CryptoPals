using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoLib
{
    public static class CryptoHelpers
    {
        ///<summary>
        ///Takes a base64 encoded string and converts it to a ASCII string, returns a string.
        ///</summary>
        public static string Base64ToAscii(string base64)
        {
            Byte[] data = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(data); ;
        }

        ///<summary>
        ///Takes a ASCII string and converts it to a Base64 string, returns a string.
        ///</summary>
        public static string AsciiToBase64(string plainText)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
        }

        ///<summary>
        ///Takes a base64 encoded string and converts it to a bytes, returns a byte array.
        ///</summary>
        public static byte[] Base64ToByteArray(string base64)
        {
            return Convert.FromBase64String(base64); 
        }

        ///<summary>
        ///Takes a byte array and converts it to a base64 encoded string, returns a string.
        ///</summary>
        public static string ByteArrayToBase64String(byte[] data)
        {
             return Convert.ToBase64String(data); 
        }

        ///<summary>
        ///Takes a hex string and converts it to a bytes, returns a byte array
        ///</summary>
        public static byte[] HexToBytes(string hex)
        {
            int NumberChars = hex.Length;
            byte[] data = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                data[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return data;
        }

        ///<summary>
        ///Takes a byte array containing data to be encrypted and a byte array with an encryption key
        ///and uses Aes.Ecb to encrypt the provided data using the provided key, returns a byte array 
        ///containing encrypted data.
        ///</summary>
        public static byte[] EcbEncrypt(byte[] data, byte[] key)
        {
            var a = new AesManaged();
            a.Key = key;
            a.Mode = CipherMode.ECB;

            var encryptor = a.CreateEncryptor();

            byte[] result = encryptor.TransformFinalBlock(data, 0, data.Length);
            return result;
        }

        ///<summary>
        ///Takes a byte array containing data to be decrypted and a byte array with an encryption key
        ///and uses Aes.Ecb to decrypt the provided data using the provided key, returns a byte array 
        ///containing decrypted data.
        ///</summary>
        public static byte[] EcbDecrypt(byte[] data, byte[] key)
        {
            var a = new AesManaged();
            a.Key = key;
            a.Mode = CipherMode.ECB;
            a.Padding = PaddingMode.PKCS7;
            var decryptor = a.CreateDecryptor();

            byte[] result = decryptor.TransformFinalBlock(data, 0, data.Length);
            return result;
        }

        ///<summary>
        ///Takes a byte array containing data to be encrypted, a byte array with an encryption key and byte array with 
        ///an initialization vector and uses Aes.Cbc to encrypt the provided data using the provided key, returns a byte array 
        ///containing decrypted data.
        ///</summary>
        public static byte[] CbcEncrypt(byte[] data, byte[] key, byte[] IVector)
        {
            var a = new AesManaged();
            a.Key = key;
            a.IV = IVector;
            a.Mode = CipherMode.CBC;

            var encryptor = a.CreateEncryptor();

            byte[] result = encryptor.TransformFinalBlock(data, 0, data.Length);
            return result;
        }

        ///<summary>
        ///Takes a byte array containing data to be encrypted and a byte array with an encryption key
        ///and uses Aes.CBC to encrypt the provided data using the provided key, returns a byte array 
        ///containing encrypted data.
        ///</summary>
        public static byte[] CbcEncrypt(byte[] data, byte[] key)
        {
            var a = new AesManaged();
            a.Key = key;
            a.Mode = CipherMode.CBC;
            a.Padding = PaddingMode.PKCS7;

            var encryptor = a.CreateEncryptor();

            byte[] result = encryptor.TransformFinalBlock(data, 0, data.Length);
            return result;
        }

        ///<summary>
        ///Takes a byte array containing data to be decrypted, a byte array with an encryption key and byte array with 
        ///an initialization vector and uses Aes.Cbc to decrypt the provided data using the provided key, returns a byte array 
        ///containing decrypted data.
        ///</summary>
        public static byte[] CbcDecrypt(byte[] data, byte[] key, byte[] IVector)
        {
            var a = new AesManaged();
            a.Key = key;
            a.IV = IVector;
            a.Mode = CipherMode.CBC;

            var decryptor = a.CreateDecryptor();

            byte[] result = decryptor.TransformFinalBlock(data, 0, data.Length);
            return result;
        }

        ///<summary>
        ///Takes a byte array containing data to be decrypted and a byte array with an encryption key
        ///and uses Aes.Cbc to decrypt the provided data using the provided key, returns a byte array 
        ///containing decrypted data.
        ///</summary>
        public static byte[] CbcDecrypt(byte[] data, byte[] key)
        {
            var a = new AesManaged();
            a.Key = key;
            a.Mode = CipherMode.CBC;

            var decryptor = a.CreateDecryptor();

            byte[] result = decryptor.TransformFinalBlock(data, 0, data.Length);
            return result;
        }

        ///<summary>
        ///Takes a byte array and padds it until it's length is a multiple of 32, pads with 0x04.
        ///</summary>
        public static byte[] Pkcs7PaddUp(byte[] data)
        {
            int padValue = 0;
            int padding = data.Length;
            
            while(padding % 16 != 0)
            {
                padding++;
                padValue++;
            }

            byte[] result = new byte[padding];
            Array.Copy(data, 0, result, 0, data.Length);

            for(int a = data.Length; a < padding; a++)
            {
                result[a] = (byte)padValue;
            }
            return result;
        }

        ///<summary>
        ///Takes a two bytes arrays as input, xors and returns the result in a byte array.
        ///</summary>
        public static byte[] FixedSizeXor(byte[] data1, byte[] data2)
        {
            byte[] xor = new byte[data1.Length];
            for(int a = 0; a < xor.Length; a++)
            {
                xor[a] = (byte)(data1[a] ^ data2[a]);
            }
            return xor;
        }

        ///<summary>
        ///Takes a two bytes arrays as encrypted data and encryption key, identifies whether CBC or ECB is used and returns the result. 
        ///Returns 0 for error/unidentified, 1 for CBC and 2 for ECB.
        ///</summary>
        public static int ECBorCBC(byte[] data, byte[] key)
        {
            /* Data to return (encryptionType)
             * 0 = error/unidentified
             * 1 = cbc
             * 2 = ecb
             */
            int encryptionType = 0;
            byte[] decrypted = new byte[data.Length];
            try
            {
                encryptionType = 1;
                decrypted = CryptoHelpers.CbcDecrypt(data, key);
            }
            catch (Exception e)
            {
                try
                {
                    encryptionType = 2;
                    decrypted = CryptoHelpers.EcbDecrypt(data, key);
                }
                catch (Exception E)
                {
                    encryptionType = 0;
                }
            }
            return encryptionType;
        }

        ///<summary>
        ///Takes a two bytes arrays as ecb encrypted data and encryption key, identifies the size of block used by identifying repeating blocks. 
        ///</summary>
        public static int IdentifyBlockSizeECB(byte[] key, byte[] encryptedData)
        {
            int keySize = 0;

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

        ///<summary>
        ///Takes a string such as "email=foo@bar.com&uid=10&role=user" and produces a dictionary of variable/value pairs.  
        ///</summary>
        public static Dictionary<string, string> cookieParser(string data)
        {
            string[] cookieParams = data.Split('&');
            Dictionary<string, string> cookieDict = new Dictionary<string, string>();

            foreach (string s in cookieParams)
            {
                string[] paramHolder = s.Split('=');
                string key = paramHolder[0];
                string value = paramHolder[1];
                cookieDict.Add(key, value);
            }

            return cookieDict;
        }

        ///<summary>
        ///Takes a Dictionary<string, string> and prodcues a string such as "email=foo@bar.com&uid=10&role=user".  
        ///</summary>
        public static string cookieGenerator(Dictionary<string, string> cookieDict)
        {
            string cookie = "";

            foreach (var v in cookieDict)
            {
                if (cookie != "")
                {
                    cookie += "&";
                }
                cookie += v.Key + "=" + v.Value;
            }
            Console.WriteLine("cookie = {0}", cookie);
            return cookie;
        }
    }
}
