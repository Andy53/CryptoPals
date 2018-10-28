using System;
using System.Text;
using CryptoLib;

namespace cryptoPalsSet2
{
    partial class Program
    {
        static string challenge16()
        {
            //Values to be worked upon.
            const string INPUT_STRING = "11111111111111111111;admin@true;";
            Console.WriteLine("Decrypte = {0}", function2(function1(INPUT_STRING)));
            return "";
        }

        static byte[] function1(string inputString)
        {
            const string PREPEND_STRING = "comment1=cooking%20MCs;userdata=";
            const string APPEND_STRING = ";comment2=%20like%20a%20pound%20of%20bacon";

            byte[] key = new byte[] { 10, 11, 23, 44, 51, 23, 34,
                89, 101, 65, 43, 71, 92, 41, 85, 03 };
            byte[] IV  = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            //Construct the string 
            string unmodified = PREPEND_STRING + inputString + APPEND_STRING;

            //Escape the required characters
            string modified = unmodified.Replace(";", " ").Replace("=", " ");

            //Convert to bytes
            byte[] plainBytes = Encoding.ASCII.GetBytes(modified);

            //Apply appropriate padding
            byte[] paddedBytes = CryptoHelpers.Pkcs7PaddUp(plainBytes);
            
            //Encrypt under CBC with key
            byte[] encryptedBytes = CryptoHelpers.CbcEncrypt(paddedBytes, key, IV);

            return encryptedBytes;
        }

        static string function2(byte[] data)
        {
            //Static values for decryption.
            byte[] IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = new byte[] { 10, 11, 23, 44, 51, 23, 34,
                89, 101, 65, 43, 71, 92, 41, 85, 03 };

            //Brute force each possible byte combination until we come up with a valid answer.
            for (int a = 0; a < 255; a++)
            {
                int holder1 = a;
                data[36] = (byte)holder1;
                string holdByte = CryptoHelpers.Base64ToAscii(
                    CryptoHelpers.ByteArrayToBase64String(CryptoHelpers.CbcDecrypt(data, key, IV)));
                if (holdByte.Contains(";admin"))
                {
                    break;
                }
            }


            for (int a = 0; a < 255; a++)
            {
                int holder2 = a;
                data[42] = (byte)holder2;
                string holdByte = CryptoHelpers.Base64ToAscii(
                    CryptoHelpers.ByteArrayToBase64String(CryptoHelpers.CbcDecrypt(data, key, IV)));
                if (holdByte.Contains(";admin=true")){
                    break;
                }
            }

            for (int a = 0; a < 255; a++)
            {
                int holder3 = a;
                data[47] = (byte)holder3;
                string holdByte = CryptoHelpers.Base64ToAscii(
                    CryptoHelpers.ByteArrayToBase64String(CryptoHelpers.CbcDecrypt(data, key, IV)));
                if (holdByte.Contains(";admin=true;"))
                {
                    break;
                }
            }

            return CryptoHelpers.Base64ToAscii(
                CryptoHelpers.ByteArrayToBase64String(CryptoHelpers.CbcDecrypt(data, key, IV)));
        }
    }
}
