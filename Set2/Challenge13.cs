using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.ComponentModel.DataAnnotations;
using CryptoLib;
using System.Text;

namespace cryptoPalsSet2
{
    partial class Program
    {
        static string challenge13()
        {
            //Static values to be used.
            string keyText = "AAAAAAAAAAAAAAAA";

            //padding so the block starting with admin decrypts correctly.
            byte[] padBytes = new byte[] { 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10 };
            string padding = Encoding.Default.GetString(padBytes);
            //1's used to ensure "admin" is the start of a 
            //block and "role=" is the end of a block
            string email = "1111111111admin" + padding + 
                "andy@evilrobots.club111111111111111";
            
            //Construct cookie string
            string cookieString = profile_for(email);

            //Convert cookie string to bytes
            byte[] key = Encoding.ASCII.GetBytes(keyText);
            byte[] cookie = Encoding.ASCII.GetBytes(cookieString);


            //Encrypt bytes with key under ecb
            byte[] encryptedCookie = CryptoHelpers.EcbEncrypt(cookie, key);
            byte[] editedCookie = new byte[encryptedCookie.Length - 16];
            byte[] adminByte = new byte[16];

            //get encrypted bytes for admin string
            for (int a = 16; a < 32; a++)
            {
                adminByte[a - 16] = encryptedCookie[a];
            }

            //Copy the encrypted bytes in the appropriate order into a new byte array.
            Array.Copy(encryptedCookie, 0, editedCookie, 0, 16);
            Array.Copy(encryptedCookie, 32, editedCookie, 16, encryptedCookie.Length - 32);
            Array.Copy(adminByte, 0, editedCookie, 64, adminByte.Length);

            Console.WriteLine(
                CryptoHelpers.Base64ToAscii(
                    CryptoHelpers.ByteArrayToBase64String(
                        CryptoHelpers.EcbDecrypt(editedCookie, key))));
            return "";
        }

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
            return cookie;
        }

        public static string profile_for(string email)
        {
            email = Regex.Replace(email, @"&quot;|['"",&?%\*:#/\\-]", " ").Trim();
            string[] holder = email.Split(" ");
            string emailValid = "";
            foreach(string s in holder)
            {
                if (new EmailAddressAttribute().IsValid(s))
                {
                    emailValid = s;
                    break;
                }
            }

            //Add uid and role onto cookie string
            string cookie = "email=" + emailValid + "&uid=10&role=user";
            return cookie; 
        }
    }
}
