namespace Effortless.Net.Encryption
{
    using System;
    using System.Globalization;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    public static class Strings
    {
        /// <summary>
        /// Encrypts a string.
        /// </summary>
        /// <param name="clearString">The plain text string.</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>The encrypted string.</returns>
        /// <exception cref="ArgumentNullException">This exception will be thrown when the original string is null.</exception>
        public static string Encrypt(string clearString, byte[] key, byte[] iv)
        {
            if(key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if(iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");
            
            if(string.IsNullOrEmpty(clearString))
                throw new ArgumentNullException("clearString");

            var cipherData = Bytes.Encrypt(new UTF8Encoding().GetBytes(clearString), key, iv);
            return Convert.ToBase64String(cipherData, 0, cipherData.Length);
        }

        /// <summary>
        /// Encrypts a string.
        /// </summary>
        /// <param name="clearString">The plain text string.</param>
        /// <param name="password">Password to create key with</param>
        /// <param name="salt">Salt to create key with</param>
        /// <param name="iv">IV</param>
        /// <param name="keySize">Can be 128, 192, or 256</param>
        /// <returns>The encrypted string.</returns>
        public static string Encrypt(string clearString, string password, string salt, string iv, Bytes.KeySize keySize)
        {
            if(string.IsNullOrEmpty(clearString)) throw new ArgumentNullException("clearString");
            if(string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");
            if(string.IsNullOrEmpty(salt)) throw new ArgumentNullException("salt");
            if(string.IsNullOrEmpty(iv)) throw new ArgumentNullException("iv");

            byte[] keyBytes = Bytes.GenerateKey(password, salt, keySize);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            return Encrypt(clearString, keyBytes, ivBytes);
        }

        /// <summary>
        /// Decrypts a string.
        /// </summary>
        /// <param name="cipherString">The encrypted string.</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>The decrypted string.</returns>
        /// <exception cref="ArgumentNullException">This exception will be thrown when the crypted string is null.</exception>
        public static string Decrypt(string cipherString, byte[] key, byte[] iv)
        {
            if(key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if(iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");
            if(string.IsNullOrEmpty(cipherString))
                throw new ArgumentNullException("cipherString");

            var clearData = Bytes.Decrypt(Convert.FromBase64String(cipherString), key, iv);
            return new UTF8Encoding().GetString(clearData);
        }

        /// <summary>
        /// Decrypts a string.
        /// </summary>
        /// <param name="cipherString">The encrypted string.</param>
        /// <param name="password">Password to create key with</param>
        /// <param name="salt">Salt to create key with</param>
        /// <param name="iv">IV</param>
        /// <param name="keySize">Can be 128, 192, or 256</param>
        /// <returns>The decrypted string.</returns>
        public static string Decrypt(string cipherString, string password, string salt, string iv, Bytes.KeySize keySize)
        {
            if(string.IsNullOrEmpty(cipherString)) throw new ArgumentNullException("cipherString");
            if(string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");
            if(string.IsNullOrEmpty(salt)) throw new ArgumentNullException("salt");
            if(string.IsNullOrEmpty(iv)) throw new ArgumentNullException("iv");

            byte[] keyBytes = Bytes.GenerateKey(password, salt, keySize);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            return Decrypt(cipherString, keyBytes, ivBytes);
        }

        /// <summary>
        /// Create a salt.
        /// </summary>
        /// <param name="size">The number of bytes the salt is required to be. This is then converted into a base64 string. The resulting string length can be larger than size.</param>
        /// <returns>A salt</returns>
        public static string CreateSaltFull(int size)
        {
            if(size < 1)
                throw new ArgumentException("size");

            var buff = new byte[size];
            new RNGCryptoServiceProvider().GetNonZeroBytes(buff);
            return Convert.ToBase64String(buff);
        }

        /// <summary>
        /// Create a salt of exactly the number of characters required.
        /// </summary>
        /// <param name="size">The number of characters required in the salt</param>
        /// <returns>A salt</returns>
        public static string CreateSalt(int size)
        {
            if(size < 1)
                throw new ArgumentException("size");

            return CreateSaltFull(size).Substring(0, size);
        }

        /// <summary>
        /// Creates a password with the required length. You can specify if you want to allow punctuation characters in the retuned password.
        /// For more information on punctuation characters, see http://msdn.microsoft.com/en-us/library/6w3ahtyy.aspx
        /// </summary>
        /// <param name="size">The number of characters in the returned password</param>
        /// <param name="allowPunctuation">If true allows letters, digits and puctuation. If false only allows letters and digits.</param>
        /// <returns>Password</returns>
        public static string CreatePassword(int size, bool allowPunctuation)
        {
            if(size < 1)
                throw new ArgumentException("size");

            var s = new StringBuilder();
            const int saltLen = 100;

            var pass = 0;
            while(pass < size)
            {
                var salt = CreateSaltFull(saltLen);
                for(var n = 0; n < saltLen; n++)
                {
                    var ch = salt[n];
                    bool punctuation = Char.IsPunctuation(ch);
                    if(!allowPunctuation && punctuation)
                        continue;

                    if(!Char.IsLetterOrDigit(ch) && !punctuation)
                        continue;

                    s.Append(ch);
                    if(++pass == size)
                        break;
                }
            }
            return s.ToString();
        }

        /// <summary>
        /// Converts the Hex string to a byte array
        /// </summary>
        /// <param name="key">Must be an even number of characters</param>
        /// <returns>Resulting byte[] array</returns>
        static public byte[] StringToHex(string key)
        {
            if(string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            var hex = new Regex("^([A-Fa-f0-9]{2}){8,9}$");
            if(!hex.IsMatch(key))
                throw new ArgumentException("Must be hexadecimal.", "key");

            var result = new byte[key.Length / 2];
            for(int index = 0; index < key.Length; index += 2)
            {
                result[index / 2] = Byte.Parse(key.Substring(index, 2), NumberStyles.AllowHexSpecifier);
            }
            return result;
        }
    }
}