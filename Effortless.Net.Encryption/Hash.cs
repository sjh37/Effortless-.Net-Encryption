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
    /// <summary>
    ///     The type of hashing function
    /// </summary>
    public enum HashType
    {
        MD5, // 128 bit
        SHA1, // 160 bit
        SHA256, // 256 bit
        SHA384, // 384 bit
        SHA512 // 512 bit
    }

    /// <summary>
    ///     A hash can help ensure authentication and integrity of data that may be
    ///     modified when transmitted between two parties. The sharedKey is shared by the two
    ///     parties who independently calculate the hash. The data is passed between parties
    ///     together with the hash. The hash will be identical if the data is unmodified.
    ///     Use a sharedKey that is sufficiently long and complex for the application -
    ///     https://www.grc.com/passwords.htm - and share the sharedKey once over a secure channel.
    ///     See http://en.wikipedia.org/wiki/Cryptographic_hash_function for more information.
    /// </summary>
    public static class Hash
    {
        private static readonly Lazy<MD5> Md5 = new Lazy<MD5>(MD5.Create);
        private static readonly Lazy<SHA1> Sha1 = new Lazy<SHA1>(SHA1.Create);
        private static readonly Lazy<SHA256> Sha256 = new Lazy<SHA256>(SHA256.Create);
        private static readonly Lazy<SHA384> Sha384 = new Lazy<SHA384>(SHA384.Create);
        private static readonly Lazy<SHA512> Sha512 = new Lazy<SHA512>(SHA512.Create);

        /// <summary>
        ///     Creates a hash and retuns the byte array of the hash
        /// </summary>
        /// <param name="hashType">The type of hash algorithm to use</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="sharedKey">The shared secret key.</param>
        public static byte[] Create(HashType hashType, string data, string sharedKey = "")
        {
            switch (hashType)
            {
                case HashType.MD5:
                    return HashData(Md5.Value, data, sharedKey);

                case HashType.SHA1:
                    return HashData(Sha1.Value, data, sharedKey);

                case HashType.SHA256:
                    return HashData(Sha256.Value, data, sharedKey);

                case HashType.SHA384:
                    return HashData(Sha384.Value, data, sharedKey);

                case HashType.SHA512:
                    return HashData(Sha512.Value, data, sharedKey);

                default:
                    throw new ArgumentOutOfRangeException(nameof(hashType));
            }
        }

        /// <summary>
        ///     Creates a hash
        /// </summary>
        /// <param name="hashType">The type of hash algorithm to use</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="sharedKey">The shared secret key.</param>
        /// <param name="showBytes">
        ///     If set to <c>true</c> will return data in hexadecimal format, i.e.
        ///     7A-C5-36-B4 without the dashes. If set to <c>false</c> will return data like xRA+Ei= etc.
        /// </param>
        public static string Create(HashType hashType, string data, string sharedKey, bool showBytes)
        {
            switch (hashType)
            {
                case HashType.MD5:
                    return HashData(Md5.Value, data, sharedKey, showBytes);

                case HashType.SHA1:
                    return HashData(Sha1.Value, data, sharedKey, showBytes);

                case HashType.SHA256:
                    return HashData(Sha256.Value, data, sharedKey, showBytes);

                case HashType.SHA384:
                    return HashData(Sha384.Value, data, sharedKey, showBytes);

                case HashType.SHA512:
                    return HashData(Sha512.Value, data, sharedKey, showBytes);

                default:
                    throw new ArgumentOutOfRangeException(nameof(hashType));
            }
        }

        public static bool Verify(HashType hashType, string data, string sharedKey, bool showBytes, string hash)
        {
            return hash == Create(hashType, data, sharedKey, showBytes);
        }

        private static byte[] HashData(HashAlgorithm hashAlgorithm, string data, string sharedKey)
        {
            if (hashAlgorithm == null) throw new ArgumentNullException(nameof(hashAlgorithm));
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (sharedKey == null) throw new ArgumentNullException(nameof(sharedKey));

            var input = Encoding.Unicode.GetBytes(data + sharedKey);
            return hashAlgorithm.ComputeHash(input);
        }

        private static string HashData(HashAlgorithm hashAlgorithm, string data, string sharedKey, bool showBytes)
        {
            var result = HashData(hashAlgorithm, data, sharedKey);
            return showBytes
                ? Bytes.ByteArrayToHex(result)
                : Convert.ToBase64String(result);
        }
    }
}