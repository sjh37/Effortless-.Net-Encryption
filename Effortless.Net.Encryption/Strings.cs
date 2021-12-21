/* The MIT License (MIT)

Copyright © Simon J Hughes 2012.
 * Homepage: http://www.hicrest.net/
 * Blog: http://simon-hughes.blogspot.co.uk/

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Security.Cryptography;
using System.Text;

namespace Effortless.Net.Encryption
{
    public static class Strings
    {
        /// <summary>
        ///     Encrypts a string. The clearString is converted into bytes, then Bytes.Encrypt() is called.
        ///     The resulting cipher data is returned after converting it to base-64.
        /// </summary>
        /// <param name="clearString">The plain text string.</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>The encrypted string.</returns>
        /// <exception cref="ArgumentNullException">This exception will be thrown when the original string is null.</exception>
        public static string Encrypt(string clearString, byte[] key, byte[] iv)
        {
            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

            if (string.IsNullOrEmpty(clearString))
                throw new ArgumentNullException(nameof(clearString));

            var cipherData = Bytes.Encrypt(new UnicodeEncoding().GetBytes(clearString), key, iv);
            return Convert.ToBase64String(cipherData, 0, cipherData.Length);
        }

        /// <summary>
        ///     Encrypts a string. The password, salt and keySize are all used to generate a key see Bytes.GenerateKey().
        ///     The iv is converted into a byte array using Encoding.Unicode.GetBytes(iv).
        ///     The other Encrypt() function is then called using the clearString, keyBytes and ivBytes.
        /// </summary>
        /// <param name="clearString">The plain text string.</param>
        /// <param name="password">Password to create key with</param>
        /// <param name="salt">Salt to create key with</param>
        /// <param name="iv">IV</param>
        /// <param name="keySize">Can be 128, 192, or 256</param>
        /// <param name="iterationCount">The number of iterations to derive the key.</param>
        /// <returns>The encrypted string.</returns>
        public static string Encrypt(string clearString, string password, string salt, string iv, Bytes.KeySize keySize,
            int iterationCount)
        {
            if (string.IsNullOrEmpty(clearString)) throw new ArgumentNullException(nameof(clearString));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(salt)) throw new ArgumentNullException(nameof(salt));
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException(nameof(iv));

            var keyBytes = Bytes.GenerateKey(password, salt, keySize, iterationCount);
            var ivBytes = Encoding.UTF8.GetBytes(iv);
            return Encrypt(clearString, keyBytes, ivBytes);
        }

        /// <summary>
        ///     Decrypts a string.
        /// </summary>
        /// <param name="cipherString">The encrypted string.</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>The decrypted string.</returns>
        /// <exception cref="ArgumentNullException">This exception will be thrown when the crypted string is null.</exception>
        public static string Decrypt(string cipherString, byte[] key, byte[] iv)
        {
            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));
            if (string.IsNullOrEmpty(cipherString))
                throw new ArgumentNullException(nameof(cipherString));

            var clearData = Bytes.Decrypt(Convert.FromBase64String(cipherString), key, iv);
            return new UnicodeEncoding().GetString(clearData);
        }

        /// <summary>
        ///     Decrypts a string.
        /// </summary>
        /// <param name="cipherString">The encrypted string.</param>
        /// <param name="password">Password to create key with</param>
        /// <param name="salt">Salt to create key with</param>
        /// <param name="iv">IV</param>
        /// <param name="keySize">Can be 128, 192, or 256</param>
        /// <param name="iterationCount">The number of iterations to derive the key.</param>
        /// <returns>The decrypted string.</returns>
        public static string Decrypt(string cipherString, string password, string salt, string iv,
            Bytes.KeySize keySize, int iterationCount)
        {
            if (string.IsNullOrEmpty(cipherString)) throw new ArgumentNullException(nameof(cipherString));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(salt)) throw new ArgumentNullException(nameof(salt));
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException(nameof(iv));

            var keyBytes = Bytes.GenerateKey(password, salt, keySize, iterationCount);
            var ivBytes = Encoding.UTF8.GetBytes(iv);
            return Decrypt(cipherString, keyBytes, ivBytes);
        }

        /// <summary>
        ///     Create a salt.
        /// </summary>
        /// <param name="numBytes">
        ///     The numBytes is the number of non zero random bytes that will converted into a base-64 string.
        ///     The resulting string length can be larger than numBytes.
        /// </param>
        /// <returns>A salt</returns>
        public static string CreateSaltFull(int numBytes)
        {
            if (numBytes < 1)
                throw new ArgumentException(nameof(numBytes));

            var buff = new byte[numBytes];
            new RNGCryptoServiceProvider().GetNonZeroBytes(buff);
            return Convert.ToBase64String(buff);
        }

        /// <summary>
        ///     Create a salt of exactly the number of characters required.
        ///     Under the hood, it calls CreateSaltFull() and trims the string to the required length.
        /// </summary>
        /// <param name="numChars">The number of characters required in the salt</param>
        /// <returns>A salt</returns>
        public static string CreateSalt(int numChars)
        {
            if (numChars < 1)
                throw new ArgumentException(nameof(numChars));

            return CreateSaltFull(numChars).Substring(0, numChars);
        }

        /// <summary>
        ///     Creates a password with the required length. You can specify if you want to allow punctuation characters in the
        ///     retuned password.
        ///     For more information on punctuation characters, see http://msdn.microsoft.com/en-us/library/6w3ahtyy.aspx
        /// </summary>
        /// <param name="size">The number of characters in the returned password</param>
        /// <param name="allowPunctuation">If true allows letters, digits and puctuation. If false only allows letters and digits.</param>
        /// <returns>Password</returns>
        public static string CreatePassword(int size, bool allowPunctuation)
        {
            if (size < 1)
                throw new ArgumentException(nameof(size));

            var s = new StringBuilder();
            const int saltLen = 100;

            var pass = 0;
            while (pass < size)
            {
                var salt = CreateSaltFull(saltLen);
                for (var n = 0; n < saltLen; n++)
                {
                    var ch = salt[n];
                    var punctuation = char.IsPunctuation(ch);
                    if (!allowPunctuation && punctuation)
                        continue;

                    if (!char.IsLetterOrDigit(ch) && !punctuation)
                        continue;

                    s.Append(ch);
                    if (++pass == size)
                        break;
                }
            }
            return s.ToString();
        }
    }
}