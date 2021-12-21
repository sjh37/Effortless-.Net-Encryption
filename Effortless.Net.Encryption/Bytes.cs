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
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Effortless.Net.Encryption
{
    public static class Bytes
    {
        public static int BufferLen = 4096;
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();
        private static PaddingMode _paddingMode = PaddingMode.ISO10126;
        private static CipherMode _cipherMode = CipherMode.CBC;

        public enum KeySize
        {
            Default = 256,
            Size128 = 128,
            Size192 = 192,
            Size256 = 256
        }

        public static void ResetPaddingAndCipherModes()
        {
            _paddingMode = PaddingMode.ISO10126;
            _cipherMode = CipherMode.CBC;
        }

        public static bool SetPaddingAndCipherModes(PaddingMode paddingMode, CipherMode cipherMode)
        {
            if (paddingMode == PaddingMode.PKCS7 && (cipherMode == CipherMode.OFB || cipherMode == CipherMode.CTS))
                return false; // invalid
            if (paddingMode == PaddingMode.Zeros)
                return false; // invalid and/or encrypt/decrypt will mismatch
            if (paddingMode == PaddingMode.ANSIX923 && (cipherMode == CipherMode.OFB || cipherMode == CipherMode.CTS))
                return false; // invalid
            if (paddingMode == PaddingMode.ISO10126 && (cipherMode == CipherMode.OFB || cipherMode == CipherMode.CTS))
                return false; // invalid

            _paddingMode = paddingMode;
            _cipherMode = cipherMode;

            return true;
        }

        private static RijndaelManaged GetRijndaelManaged(byte[] key, byte[] iv, KeySize keySize)
        {
            var rm = new RijndaelManaged
            {
                KeySize   = (int) keySize,
                BlockSize = 128,
                Padding   = _paddingMode,
                Mode      = _cipherMode
            };

            if (key != null)
                rm.Key = key;

            if (iv != null)
                rm.IV = iv;

            return rm;
        }

        /// <summary>
        ///     Returns an encryption key to be used with the Rijndael algorithm
        /// </summary>
        public static byte[] GenerateKey()
        {
            return GenerateKey(KeySize.Default);
        }

        /// <summary>
        ///     Returns an encryption key to be used with the Rijndael algorithm
        /// </summary>
        public static byte[] GenerateKey(KeySize keySize)
        {
            using (var rm = GetRijndaelManaged(null, null, keySize))
            {
                rm.GenerateKey();
                return rm.Key;
            }
        }

        /// <summary>
        ///     Returns an encryption key to be used with the Rijndael algorithm
        /// </summary>
        /// <param name="password">Password to create key with</param>
        /// <param name="salt">Salt to create key with</param>
        /// <param name="keySize">Can be 128, 192, or 256</param>
        /// <param name="iterationCount">The number of iterations to derive the key.</param>
        public static byte[] GenerateKey(string password, string salt, KeySize keySize, int iterationCount)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(salt)) throw new ArgumentNullException(nameof(salt));

            var saltValueBytes = Encoding.Unicode.GetBytes(salt);
            if (saltValueBytes.Length < 8)
                throw new ArgumentException("Salt is not at least eight bytes");

            var derivedPassword = new Rfc2898DeriveBytes(password, saltValueBytes, iterationCount);
            return derivedPassword.GetBytes((int) keySize / 8);
        }

        /// <summary>
        ///     Returns the encryption IV to be used with the Rijndael algorithm
        /// </summary>
        public static byte[] GenerateIV()
        {
            return GenerateIV(KeySize.Default);
        }
        
        /// <summary>
        ///     Returns the encryption IV to be used with the Rijndael algorithm
        /// </summary>
        public static byte[] GenerateIV(KeySize keySize)
        {
            using (var rm = GetRijndaelManaged(null, null, keySize))
            {
                rm.GenerateIV();
                return rm.IV;
            }
        }

        /// <summary>
        ///     Encrypt a byte array into a byte array using the given Key and an IV
        /// </summary>
        public static byte[] Encrypt(byte[] clearData, byte[] key, byte[] iv)
        {
            return Encrypt(clearData, key, iv, KeySize.Default);
        }

        /// <summary>
        ///     Encrypt a byte array into a byte array using the given Key and an IV
        /// </summary>
        public static byte[] Encrypt(byte[] clearData, byte[] key, byte[] iv, KeySize keySize)
        {
            if (clearData == null || clearData.Length <= 0) throw new ArgumentNullException(nameof(clearData));
            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

            // Create a MemoryStream to accept the encrypted bytes
            var memoryStream = new MemoryStream();

            // Create a symmetric algorithm.
            // We are going to use Rijndael because it is strong and available on all platforms.
            // You can use other algorithms, to do so substitute the next line with something like
            // TripleDES alg = TripleDES.Create();
            using (var alg = GetRijndaelManaged(key, iv, keySize))
            {
                // Create a CryptoStream through which we are going to be pumping our data.
                // CryptoStreamMode.Write means that we are going to be writing data to the stream and the
                // output will be written in the MemoryStream we have provided.
                using (var cs = new CryptoStream(memoryStream, alg.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    // Write the data and make it do the encryption
                    cs.Write(clearData, 0, clearData.Length);

                    // Close the crypto stream (or do FlushFinalBlock).
                    // This will tell it that we have done our encryption and there is no more data coming in,
                    // and it is now a good time to apply the padding and finalize the encryption process.
                    cs.FlushFinalBlock();
                    cs.Close();
                }
            }

            // Now get the encrypted data from the MemoryStream.
            // Some people make a mistake of using GetBuffer() here, which is not the right way.
            var encryptedData = memoryStream.ToArray();

            return encryptedData;
        }

        /// <summary>
        ///     Encrypt a file into another file.
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, RijndaelManaged alg)
        {
            if (clearStreamIn == null) throw new ArgumentNullException(nameof(clearStreamIn));
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException(nameof(encryptedFileOut));
            if (alg == null) throw new ArgumentNullException(nameof(alg));

            // First we are going to open the file streams
            using (var fsOut = new FileStream(encryptedFileOut, FileMode.OpenOrCreate, FileAccess.Write))
            {
                // Now create a crypto stream through which we are going to be pumping data.
                // Our encryptedFileOut is going to be receiving the encrypted bytes.
                using (var cs = new CryptoStream(fsOut, alg.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    // Now will will initialize a buffer and will be processing the input file in chunks.
                    // This is done to avoid reading the whole file (which can be huge) into memory.
                    var buffer = new byte[BufferLen];
                    int bytesRead;

                    do
                    {
                        bytesRead = clearStreamIn.Read(buffer, 0, BufferLen); // Read a chunk of data from the input file
                        if (bytesRead > 0)
                            cs.Write(buffer, 0, bytesRead); // Encrypt it
                    } while (bytesRead != 0);

                    // Close everything. This will also close the unrelying clearStreamOut stream
                    cs.FlushFinalBlock();
                    cs.Close();
                }
                clearStreamIn.Close();
            }
        }

        /// <summary>
        ///     Encrypt a file into another file
        /// </summary>
        public static void Encrypt(string clearFileIn, string encryptedFileOut, byte[] key, byte[] iv)
        {
            Encrypt(clearFileIn, encryptedFileOut, key, iv, KeySize.Default);
        }

        /// <summary>
        ///     Encrypt a file into another file
        /// </summary>
        public static void Encrypt(string clearFileIn, string encryptedFileOut, byte[] key, byte[] iv, KeySize keySize)
        {
            if (string.IsNullOrEmpty(clearFileIn)) throw new ArgumentNullException(nameof(clearFileIn));
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException(nameof(encryptedFileOut));

            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

            using (var alg = GetRijndaelManaged(key, iv, keySize))
            {
                using (var fsIn = new FileStream(clearFileIn, FileMode.Open, FileAccess.Read))
                {
                    Encrypt(fsIn, encryptedFileOut, alg);
                }
            }
        }

        /// <summary>
        ///     Encrypt a stream into a file
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, byte[] key, byte[] iv)
        {
            Encrypt(clearStreamIn, encryptedFileOut, key, iv, KeySize.Default);
        }

        /// <summary>
        ///     Encrypt a stream into a file
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, byte[] key, byte[] iv, KeySize keySize)
        {
            if (clearStreamIn == null) throw new ArgumentNullException(nameof(clearStreamIn));
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException(nameof(encryptedFileOut));
            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

            using (var alg = GetRijndaelManaged(key, iv, keySize))
            {
                Encrypt(clearStreamIn, encryptedFileOut, alg);
            }
        }

        /// <summary>
        ///     Encrypt a file into another file.
        ///     The Key and an IV are automatically generated. These will be required when Decrypting the data.
        /// </summary>
        public static void Encrypt(string clearFileIn, string encryptedFileOut, out string key, out string iv)
        {
            Encrypt(clearFileIn, encryptedFileOut, KeySize.Default, out key, out iv);
        }

        /// <summary>
        ///     Encrypt a file into another file.
        ///     The Key and an IV are automatically generated. These will be required when Decrypting the data.
        /// </summary>
        public static void Encrypt(string clearFileIn, string encryptedFileOut, KeySize keySize, out string key, out string iv)
        {
            if (string.IsNullOrEmpty(clearFileIn)) throw new ArgumentNullException(nameof(clearFileIn));
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException(nameof(encryptedFileOut));

            using (var alg = GetRijndaelManaged(null, null, keySize))
            {
                alg.GenerateIV();
                alg.GenerateKey();

                key = Convert.ToBase64String(alg.Key);
                iv = Convert.ToBase64String(alg.IV);

                using (var fsIn = new FileStream(clearFileIn, FileMode.Open, FileAccess.Read))
                {
                    Encrypt(fsIn, encryptedFileOut, alg);
                }
            }
        }

        /// <summary>
        ///     Encrypt a stream into a file.
        ///     The Key and an IV are automatically generated. These will be required when Decrypting the data.
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, out string key, out string iv)
        {
            Encrypt(clearStreamIn, encryptedFileOut, KeySize.Default, out key, out iv);
        }

        /// <summary>
        ///     Encrypt a stream into a file.
        ///     The Key and an IV are automatically generated. These will be required when Decrypting the data.
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, KeySize keySize, out string key, out string iv)
        {
            if (clearStreamIn == null) throw new ArgumentNullException(nameof(clearStreamIn));
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException(nameof(encryptedFileOut));

            using (var alg = GetRijndaelManaged(null, null, keySize))
            {
                alg.GenerateIV();
                alg.GenerateKey();

                key = Convert.ToBase64String(alg.Key);
                iv = Convert.ToBase64String(alg.IV);

                Encrypt(clearStreamIn, encryptedFileOut, alg);
            }
        }

        /// <summary>
        ///     Decrypt a byte array into a byte array using a Key and an IV
        /// </summary>
        public static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv)
        {
            return Decrypt(cipherData, key, iv, KeySize.Default);
        }

        /// <summary>
        ///     Decrypt a byte array into a byte array using a Key and an IV
        /// </summary>
        public static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv, KeySize keySize)
        {
            if (cipherData == null) throw new ArgumentNullException(nameof(cipherData));
            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

            if (cipherData.Length < 1) throw new ArgumentException("cipherData");

            // Create a MemoryStream that is going to accept the decrypted bytes
            using (var memoryStream = new MemoryStream())
            {
                // Create a symmetric algorithm.
                // We are going to use Rijndael because it is strong and available on all platforms.
                // You can use other algorithms, to do so substitute the next line with something like
                // TripleDES alg = TripleDES.Create();
                using (var alg = GetRijndaelManaged(key, iv, keySize))
                {
                    // Create a CryptoStream through which we are going to be pumping our data.
                    // CryptoStreamMode.Write means that we are going to be writing data to the stream
                    // and the output will be written in the MemoryStream we have provided.
                    using (var cs = new CryptoStream(memoryStream, alg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        // Write the data and make it do the decryption
                        cs.Write(cipherData, 0, cipherData.Length);

                        // Close the crypto stream (or do FlushFinalBlock).
                        // This will tell it that we have done our decryption and there is no more data coming in,
                        // and it is now a good time to remove the padding and finalize the decryption process.
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                }

                // Now get the decrypted data from the MemoryStream.
                // Some people make a mistake of using GetBuffer() here, which is not the right way.
                var decryptedData = memoryStream.ToArray();
                return decryptedData;
            }
        }

        /// <summary>
        ///     Decrypt a file into another file
        /// </summary>
        public static void Decrypt(Stream encryptedStreamIn, Stream clearStreamOut, RijndaelManaged alg)
        {
            if (encryptedStreamIn == null) throw new ArgumentNullException(nameof(encryptedStreamIn));
            if (clearStreamOut == null) throw new ArgumentNullException(nameof(clearStreamOut));
            if (alg == null) throw new ArgumentNullException(nameof(alg));

            // Now create a crypto stream through which we are going to be pumping data.
            // Our encryptedFileOut is going to be receiving the Decrypted bytes.
            var cs = new CryptoStream(clearStreamOut, alg.CreateDecryptor(), CryptoStreamMode.Write);

            // Now will will initialize a buffer and will be processing the input file in chunks.
            // This is done to avoid reading the whole file (which can be huge) into memory.
            var buffer = new byte[BufferLen];
            int bytesRead;

            do
            {
                bytesRead = encryptedStreamIn.Read(buffer, 0, BufferLen); // Read a chunk of data from the input file
                if (bytesRead > 0)
                    cs.Write(buffer, 0, bytesRead); // Decrypt it
            } while (bytesRead != 0);

            // Close everything
            cs.FlushFinalBlock();
            //cs.Close(); // Causes an exception when streaming to http
            encryptedStreamIn.Close();
        }

        /// <summary>
        ///     Decrypt a file into another file
        /// </summary>
        public static void Decrypt(string encryptedFileIn, string clearFileOut, byte[] key, byte[] iv)
        {
            Decrypt(encryptedFileIn, clearFileOut, key, iv, KeySize.Default);
        }

        /// <summary>
        ///     Decrypt a file into another file
        /// </summary>
        public static void Decrypt(string encryptedFileIn, string clearFileOut, byte[] key, byte[] iv, KeySize keySize)
        {
            if (string.IsNullOrEmpty(encryptedFileIn)) throw new ArgumentNullException(nameof(encryptedFileIn));
            if (string.IsNullOrEmpty(clearFileOut)) throw new ArgumentNullException(nameof(clearFileOut));
            if (key == null || key.Length <= 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

            // First we are going to open the file streams
            using (var fsIn = new FileStream(encryptedFileIn, FileMode.Open, FileAccess.Read))
            {
                using (var fsOut = new FileStream(clearFileOut, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    using (var alg = GetRijndaelManaged(key, iv, keySize))
                    {
                        Decrypt(fsIn, fsOut, alg);
                    }
                }
            }
        }

        /// <summary>
        ///     Decrypt a file into another file using a Key and an IV
        /// </summary>
        public static void Decrypt(string encryptedFileIn, string clearFileOut, string key, string iv)
        {
            if (string.IsNullOrEmpty(encryptedFileIn)) throw new ArgumentNullException(nameof(encryptedFileIn));
            if (string.IsNullOrEmpty(clearFileOut)) throw new ArgumentNullException(nameof(clearFileOut));
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException(nameof(iv));

            Decrypt(encryptedFileIn, clearFileOut, Convert.FromBase64String(key), Convert.FromBase64String(iv));
        }

        /// <summary>
        ///     Decrypt a file into another file using a Key and an IV
        /// </summary>
        public static void Decrypt(string encryptedFileIn, Stream clearStreamOut, string key, string iv)
        {
            Decrypt(encryptedFileIn, clearStreamOut, key, iv, KeySize.Default);
        }

        /// <summary>
        ///     Decrypt a file into another file using a Key and an IV
        /// </summary>
        public static void Decrypt(string encryptedFileIn, Stream clearStreamOut, string key, string iv, KeySize keySize)
        {
            if (encryptedFileIn == null) throw new ArgumentNullException(nameof(encryptedFileIn));
            if (clearStreamOut == null) throw new ArgumentNullException(nameof(clearStreamOut));
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException(nameof(iv));

            using (var fsIn = new FileStream(encryptedFileIn, FileMode.Open, FileAccess.Read))
            {
                using (var alg = GetRijndaelManaged(Convert.FromBase64String(key), Convert.FromBase64String(iv), keySize))
                {
                    Decrypt(fsIn, clearStreamOut, alg);
                }
            }
        }

        /// <summary>
        /// Converts HEX string to byte array.
        /// Opposite of ByteArrayToHex.
        /// </summary>
        public static byte[] HexToByteArray(string hexString)
        {
            if (hexString == null) throw new ArgumentNullException(nameof(hexString));

            if ((hexString.Length % 2) != 0)
                throw new ApplicationException("Hex string must be multiple of 2 in length");

            var byteCount = hexString.Length / 2;
            var byteValues = new byte[byteCount];
            for (var i = 0; i < byteCount; i++)
            {
                byteValues[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return byteValues;
        }

        /// <summary>
        /// Convert bytes to 2 hex characters per byte, "-" separators are removed.
        /// Opposite of HexToByteArray
        /// </summary>
        public static string ByteArrayToHex(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            return BitConverter.ToString(data).Replace("-", "");
        }

        /// <summary>
        /// Use cryptographically strong random number generator to fill buffer with random data.
        /// </summary>
        public static void GetRandomBytes(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            Rng.GetBytes(buffer);
        }
    }
}