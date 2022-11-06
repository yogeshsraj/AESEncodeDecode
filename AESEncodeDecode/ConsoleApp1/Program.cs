using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {

                string original = "PlatformLogin!23#";
                using (RijndaelManaged myRijndael = new RijndaelManaged())
                {
                    //Branch Switching Test
                    //Main Branch
                    //myRijndael.GenerateKey();
                    //myRijndael.GenerateIV();
                    myRijndael.Key = Encoding.UTF8.GetBytes("8080808080808080");
                    myRijndael.IV = Encoding.UTF8.GetBytes("8080808080808080");

                    byte[] encrypted = EncryptStringToBytes(original,
                                       myRijndael.Key, myRijndael.IV);
                    var passwordencrypted = Convert.ToBase64String(encrypted);
                    string aftdecryp = DecryptStringFromBytes(encrypted,
                                       myRijndael.Key, myRijndael.IV);
                    Console.WriteLine("Original:   {0}", original);
                    Console.WriteLine("After Decryption: {0}", aftdecryp);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key,
                                             rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt,
                            encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }
        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key,
                                             rijAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt,
                           decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }
    }
}
