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

namespace Effortless.Net.Encryption
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public static class Bytes
    {
        public enum KeySize
        {
            Size128 = 128,
            Size192 = 192,
            Size256 = 256
        }

        private static RijndaelManaged GetRijndaelManaged(byte[] key, byte[] iv)
        {
            var rm = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 256,
                Padding = PaddingMode.ISO10126,
                Mode = CipherMode.CBC
            };

            if (key != null)
                rm.Key = key;

            if (iv != null)
                rm.IV = iv;

            return rm;
        }

        /// <summary>
        /// Returns an encryption key to be used with the Rijndael algorithm
        /// </summary>
        public static byte[] GenerateKey()
        {
            using (var rm = GetRijndaelManaged(null, null))
            {
                rm.GenerateKey();
                return rm.Key;
            }
        }

        /// <summary>
        /// Returns an encryption key to be used with the Rijndael algorithm
        /// </summary>
        /// <param name="password">Password to create key with</param>
        /// <param name="salt">Salt to create key with</param>
        /// <param name="keySize">Can be 128, 192, or 256</param>
        public static byte[] GenerateKey(string password, string salt, KeySize keySize)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");
            if (string.IsNullOrEmpty(salt)) throw new ArgumentNullException("salt");

            var saltValueBytes	= Encoding.UTF8.GetBytes(salt);
            if (saltValueBytes.Length < 8)
                throw new ArgumentException("Salt is not at least eight bytes");

            var derivedPassword = new Rfc2898DeriveBytes(password, saltValueBytes);
            return derivedPassword.GetBytes((int)keySize / 8);
        }

        /// <summary>
        /// Returns the encryption IV to be used with the Rijndael algorithm
        /// </summary>
        public static byte[] GenerateIV()
        {
            using (var rm = GetRijndaelManaged(null, null))
            {
                rm.GenerateIV();
                return rm.IV;
            }
        }

        /// <summary>
        /// Encrypt a byte array into a byte array using the given Key and an IV
        /// </summary>
        public static byte[] Encrypt(byte[] clearData, byte[] key, byte[] iv)
        {
            if (clearData == null || clearData.Length <= 0) throw new ArgumentNullException("clearData");
            if (key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");

            // Create a MemoryStream to accept the encrypted bytes 
            var memoryStream = new MemoryStream();

            // Create a symmetric algorithm. 
            // We are going to use Rijndael because it is strong and available on all platforms. 
            // You can use other algorithms, to do so substitute the next line with something like 
            // TripleDES alg = TripleDES.Create(); 
            using (var alg = GetRijndaelManaged(key, iv))
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
        /// Encrypt a file into another file.
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, RijndaelManaged alg)
        {
            if (clearStreamIn == null) throw new ArgumentNullException("clearStreamIn");
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException("encryptedFileOut");
            if (alg == null) throw new ArgumentNullException("alg");

            // First we are going to open the file streams
            using (var fsOut = new FileStream(encryptedFileOut, FileMode.OpenOrCreate, FileAccess.Write))
            {
                // Now create a crypto stream through which we are going to be pumping data.
                // Our encryptedFileOut is going to be receiving the encrypted bytes. 
                using (var cs = new CryptoStream(fsOut, alg.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    // Now will will initialize a buffer and will be processing the input file in chunks. 
                    // This is done to avoid reading the whole file (which can be huge) into memory. 
                    const int bufferLen = 4096;
                    var buffer = new byte[bufferLen];
                    int bytesRead;

                    do
                    {
                        bytesRead = clearStreamIn.Read(buffer, 0, bufferLen); // Read a chunk of data from the input file 
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
        /// Encrypt a file into another file
        /// </summary>
        public static void Encrypt(string clearFileIn, string encryptedFileOut, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(clearFileIn)) throw new ArgumentNullException("clearFileIn");
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException("encryptedFileOut");

            if (key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");

            using (var alg = GetRijndaelManaged(key, iv))
            {
                using (var fsIn = new FileStream(clearFileIn, FileMode.Open, FileAccess.Read))
                {
                    Encrypt(fsIn, encryptedFileOut, alg);
                }
            }
        }

        /// <summary>
        /// Encrypt a stream into a file
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, byte[] key, byte[] iv)
        {
            if (clearStreamIn == null) throw new ArgumentNullException("clearStreamIn");
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException("encryptedFileOut");
            if (key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");

            using (var alg = GetRijndaelManaged(key, iv))
            {
                Encrypt(clearStreamIn, encryptedFileOut, alg);
            }
        }

        /// <summary>
        /// Encrypt a file into another file.
        /// The Key and an IV are automatically generated. These will be required when Decrypting the data.
        /// </summary>
        public static void Encrypt(string clearFileIn, string encryptedFileOut, out string key, out string iv)
        {
            if (string.IsNullOrEmpty(clearFileIn)) throw new ArgumentNullException("clearFileIn");
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException("encryptedFileOut");

            using (var alg = GetRijndaelManaged(null, null))
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
        /// Encrypt a stream into a file.
        /// The Key and an IV are automatically generated. These will be required when Decrypting the data.
        /// </summary>
        public static void Encrypt(Stream clearStreamIn, string encryptedFileOut, out string key, out string iv)
        {
            if (clearStreamIn == null) throw new ArgumentNullException("clearStreamIn");
            if (string.IsNullOrEmpty(encryptedFileOut)) throw new ArgumentNullException("encryptedFileOut");

            using (var alg = GetRijndaelManaged(null, null))
            {
                alg.GenerateIV();
                alg.GenerateKey();

                key = Convert.ToBase64String(alg.Key);
                iv = Convert.ToBase64String(alg.IV);

                Encrypt(clearStreamIn, encryptedFileOut, alg);
            }
        }

        /// <summary>
        /// Decrypt a byte array into a byte array using a Key and an IV
        /// </summary>
        public static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv)
        {
            if (cipherData == null) throw new ArgumentNullException("cipherData");
            if (key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");

            if (cipherData.Length < 1) throw new ArgumentException("cipherData");

            // Create a MemoryStream that is going to accept the decrypted bytes 
            using (var memoryStream = new MemoryStream())
            {
                // Create a symmetric algorithm.
                // We are going to use Rijndael because it is strong and available on all platforms. 
                // You can use other algorithms, to do so substitute the next line with something like 
                // TripleDES alg = TripleDES.Create();
                using (var alg = GetRijndaelManaged(key, iv))
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
        /// Decrypt a file into another file
        /// </summary>
        public static void Decrypt(Stream encryptedStreamIn, Stream clearStreamOut, RijndaelManaged alg)
        {
            if (encryptedStreamIn == null) throw new ArgumentNullException("encryptedStreamIn");
            if (clearStreamOut == null) throw new ArgumentNullException("clearStreamOut");
            if (alg == null) throw new ArgumentNullException("alg");

            // Now create a crypto stream through which we are going to be pumping data. 
            // Our encryptedFileOut is going to be receiving the Decrypted bytes. 
            var cs = new CryptoStream(clearStreamOut, alg.CreateDecryptor(), CryptoStreamMode.Write);

            // Now will will initialize a buffer and will be processing the input file in chunks. 
            // This is done to avoid reading the whole file (which can be huge) into memory. 
            const int bufferLen = 4096;
            var buffer = new byte[bufferLen];
            int bytesRead;

            do
            {
                bytesRead = encryptedStreamIn.Read(buffer, 0, bufferLen); // Read a chunk of data from the input file 
                if (bytesRead > 0)
                    cs.Write(buffer, 0, bytesRead); // Decrypt it 
            } while (bytesRead != 0);

            // Close everything 
            cs.FlushFinalBlock();
            //cs.Close(); // Causes an exception when streaming to http
            encryptedStreamIn.Close();
        }

        /// <summary>
        /// Decrypt a file into another file
        /// </summary>
        public static void Decrypt(string encryptedFileIn, string clearFileOut, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(encryptedFileIn)) throw new ArgumentNullException("encryptedFileIn");
            if (string.IsNullOrEmpty(clearFileOut)) throw new ArgumentNullException("clearFileOut");
            if (key == null || key.Length <= 0) throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0) throw new ArgumentNullException("iv");

            // First we are going to open the file streams 
            using (var fsIn = new FileStream(encryptedFileIn, FileMode.Open, FileAccess.Read))
            {
                using (var fsOut = new FileStream(clearFileOut, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    using (var alg = GetRijndaelManaged(key, iv))
                    {
                        Decrypt(fsIn, fsOut, alg);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt a file into another file using a Key and an IV
        /// </summary>
        public static void Decrypt(string encryptedFileIn, string clearFileOut, string key, string iv)
        {
            if (string.IsNullOrEmpty(encryptedFileIn)) throw new ArgumentNullException("encryptedFileIn");
            if (string.IsNullOrEmpty(clearFileOut)) throw new ArgumentNullException("clearFileOut");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("key");
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException("iv");

            Decrypt(encryptedFileIn, clearFileOut, Convert.FromBase64String(key), Convert.FromBase64String(iv));
        }

        /// <summary>
        /// Decrypt a file into another file using a Key and an IV
        /// </summary>
        public static void Decrypt(string encryptedFileIn, Stream clearStreamOut, string key, string iv)
        {
            if (encryptedFileIn == null) throw new ArgumentNullException("encryptedFileIn");
            if (clearStreamOut == null) throw new ArgumentNullException("clearStreamOut");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("key");
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException("iv");

            using (var fsIn = new FileStream(encryptedFileIn, FileMode.Open, FileAccess.Read))
            {
                using (var alg = GetRijndaelManaged(Convert.FromBase64String(key), Convert.FromBase64String(iv)))
                {
                    Decrypt(fsIn, clearStreamOut, alg);
                }
            }
        }
    }
}