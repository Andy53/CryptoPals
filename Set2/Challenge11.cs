using System;
using System.Text;
using CryptoLib;

namespace cryptoPalsSet2
{
    partial class Program
    {
        static string challenge11()
        {
            //Create plaintext string and random key.
            byte[] plainText = Encoding.ASCII.GetBytes(
                "\"Nothing is particularly hard if you divide it into small jobs.\" — Henry Ford");
            byte[] key = new byte[16];
            Random random = new Random();
            random.NextBytes(key);

            //Create padding arrays and fill with random bytes
            byte[] firstPad = new byte[random.Next(5, 10)];
            random.NextBytes(firstPad);
            byte[] secondPad = new byte[random.Next(5, 10)];
            random.NextBytes(secondPad);

            //Create an array to store randomized plain text, 
            //then combine data from existing arrays into plainBytes
            byte[] plainBytes = new byte[firstPad.Length + plainText.Length + secondPad.Length];
            Array.Copy(firstPad, 0, plainBytes, 0, firstPad.Length);
            Array.Copy(plainText, 0, plainBytes, firstPad.Length, plainText.Length);
            Array.Copy(secondPad, 0, plainBytes, 
                firstPad.Length + plainText.Length, secondPad.Length);

            byte[] IVector = new byte[] { 00, 00, 00, 00, 00, 00, 00,
                00, 00, 00, 00, 00, 00, 00, 00, 00 };

            byte[] encrpyted = CryptoHelpers.Pkcs7PaddUp(plainBytes);
            int whichEncrypyMethod = random.Next(2);
            whichEncrypyMethod = 1;

            //Attempt encryption functions.
            if (whichEncrypyMethod == 0)
            {
                encrpyted = CryptoHelpers.CbcEncrypt(encrpyted, key, IVector);
                Console.WriteLine("Encrypted with CBC decryption");
            }
            else if(whichEncrypyMethod == 1)
            {
                encrpyted = CryptoHelpers.EcbEncrypt(encrpyted, key);
                Console.WriteLine("Encrypted with ECB decryption");
            }
            else
            {
                Console.WriteLine("Else statement hit, this is an issue");
            }

            Console.WriteLine("Encrypted: {0}", Encoding.Default.GetString(encrpyted));

            //Attempt decryption.
            byte[] decrypted = new byte[encrpyted.Length];
            try
            {
                decrypted = CryptoHelpers.CbcDecrypt(encrpyted, key, IVector);
                Console.WriteLine("Decrypted: {0}", Encoding.Default.GetString(decrypted));
                Console.WriteLine("Decrypted with CBC decryption");
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
                try
                {
                    decrypted = CryptoHelpers.EcbDecrypt(encrpyted, key);
                    Console.WriteLine("Decrypted: {0}", Encoding.Default.GetString(decrypted));
                    Console.WriteLine("Decrypted with ECB decryption");
                }
                catch(Exception E)
                {
                    Console.WriteLine(E);
                    Console.WriteLine("Back to the drawing board.");
                }
            }

            int test = CryptoHelpers.ECBorCBC(encrpyted, key);
            Console.WriteLine(test);
            return "";
        }
    }
}
