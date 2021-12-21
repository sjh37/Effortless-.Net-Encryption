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

namespace Effortless.Net.Encryption
{
    public class Digest
    {
        /// <summary>
        ///     Constructor where you can define all the properties.
        /// </summary>
        /// <param name="data">The data</param>
        /// <param name="hash">The hash</param>
        /// <param name="hashType">The HashType used to generate the hash.</param>
        public Digest(string data, string hash, HashType hashType)
        {
            Data = data;
            Hash = hash;
            HashType = hashType;
        }

        // Returns the data
        public string Data { get; }

        /// <summary>
        ///     Returns the pre-computed hash.
        /// </summary>
        public string Hash { get; }

        /// <summary>
        ///     Returns the hash type used to generate the hash
        /// </summary>
        public HashType HashType { get; }

        /// <summary>
        ///     Static function to create a Digest.
        /// </summary>
        /// <param name="hashType">HashType algorithm to be used to generate the hash</param>
        /// <param name="data">The data</param>
        /// <param name="sharedKey">
        ///     The sharedKey is shared by the two parties who independently calculate the hash. The data is passed between parties
        ///     together with the hash. The hash will be identical if the data is unmodified. Use a sharedKey that is sufficiently
        ///     long and complex for the application - https://www.grc.com/passwords.htm - and share the sharedKey once over a
        ///     secure channel. See http://en.wikipedia.org/wiki/Cryptographic_hash_function for more information.
        /// </param>
        /// <returns>A Digest class.</returns>
        public static Digest Create(HashType hashType, string data, string sharedKey)
        {
            var hash = Encryption.Hash.Create(hashType, data, sharedKey, true);
            return new Digest(data, hash, hashType);
        }

        /// <summary>
        ///     Returns a string in the following format: XXYYYH*D*
        ///     Where XX is the hashType, YYYY is the length of the hash, H* is the hash, and D* is the data.
        /// </summary>
        /// <returns>A string representing the Digest.</returns>
        public override string ToString()
        {
            var hashType = ((int) HashType).ToString("d2");
            var hashLength = Hash.Length.ToString("d3");
            return hashType + hashLength + Hash + Data;
        }

        /// <summary>
        ///     This is the opposite of ToString(). It takes the data and re-creates the Digest.
        /// </summary>
        /// <param name="hashedData">The data obtained from ToString()</param>
        /// <param name="sharedKey">
        ///     The sharedKey is shared by the two parties who independently calculate the hash. The data is passed between parties
        ///     together with the hash. The hash will be identical if the data is unmodified. Use a sharedKey that is sufficiently
        ///     long and complex for the application - https://www.grc.com/passwords.htm - and share the sharedKey once over a
        ///     secure channel. See http://en.wikipedia.org/wiki/Cryptographic_hash_function for more information.
        /// </param>
        /// <returns>Returns a Digest if succesfully verified, otherwise returns null</returns>
        public static Digest CreateFromString(string hashedData, string sharedKey)
        {
            if (string.IsNullOrEmpty(hashedData))
                throw new ArgumentNullException(nameof(hashedData));
            if (sharedKey == null)
                throw new ArgumentNullException(nameof(sharedKey));

            if (hashedData.Length < 12)
                return null; // Not long enough to cover even the smallest

            var hashType = (HashType) int.Parse(hashedData.Substring(0, 2));

            int.TryParse(hashedData.Substring(2, 3), out var hashLength);
            if (hashLength < 0)
                return null;

            if (hashedData.Length < hashLength + 5)
                return null;

            var hash = hashedData.Substring(5, hashLength);
            var data = hashedData.Substring(5 + hashLength);

            // Validate
            if (hash != Encryption.Hash.Create(hashType, data, sharedKey, true))
                return null;

            return new Digest(data, hash, hashType);
        }

        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;
            if (Hash == null)
                throw new ArgumentException("_hash");
            if (!(obj is Digest))
                throw new ArgumentException("obj is not a Digest");

            var other = obj as Digest;
            var toString = other.ToString();
            if (toString == null)
                throw new ArgumentNullException(nameof(obj));
            return toString.Equals(ToString());
        }

        public override int GetHashCode()
        {
            if (Data == null)
                throw new ArgumentException("_data");
            return Data.GetHashCode();
        }

        #region Operator overloads

        public static bool operator ==(Digest a, Digest b)
        {
            if ((object) a == null)
                throw new ArgumentNullException(nameof(a));
            if ((object) b == null)
                throw new ArgumentNullException(nameof(b));
            return a.Equals(b);
        }

        public static bool operator ==(Digest a, string b)
        {
            if ((object) a == null)
                throw new ArgumentNullException(nameof(a));
            if (b == null)
                throw new ArgumentNullException(nameof(b));
            var toString = a.ToString();
            if (toString == null)
                throw new ArgumentNullException(nameof(a));
            return toString.Equals(b);
        }

        public static bool operator ==(string a, Digest b)
        {
            return b == a;
        }

        public static bool operator !=(Digest a, string b)
        {
            return !(a == b);
        }

        public static bool operator !=(Digest a, Digest b)
        {
            return !(a == b);
        }

        public static bool operator !=(string a, Digest b)
        {
            return !(b == a);
        }

        #endregion
    }
}