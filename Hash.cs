namespace Effortless.Net.Encryption
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// The type of hashing function
    /// </summary>
    public enum HashType
    {
        MD5, 
        SHA1, 
        SHA256, 
        SHA384, 
        SHA512
    }

    /// <summary>
    /// A hash can help ensure authentication and integrity of data that may be
    /// modified when transmitted between two parties. The sharedKey is shared by the two
    /// parties who independently calculate the hash. The data is passed between parties
    /// together with the hash. The hash will be identical if the data is unmodified.
    /// Use a sharedKey that is sufficiently long and complex for the application -
    /// https://www.grc.com/passwords.htm - and share the sharedKey once over a secure channel.
    /// See http://en.wikipedia.org/wiki/Cryptographic_hash_function for more information.
    /// </summary>
    public static class Hash
    {
        private static readonly Lazy<MD5> Md5 = new Lazy<MD5>(MD5.Create);
        private static readonly Lazy<SHA1> Sha1 = new Lazy<SHA1>(SHA1.Create);
        private static readonly Lazy<SHA256> Sha256 = new Lazy<SHA256>(SHA256.Create);
        private static readonly Lazy<SHA384> Sha384 = new Lazy<SHA384>(SHA384.Create);
        private static readonly Lazy<SHA512> Sha512 = new Lazy<SHA512>(SHA512.Create);

        /// <summary>
        /// Creates a hash
        /// </summary>
        /// <param name="hashType">The type of hash algorithm to use</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="sharedKey">The shared secret key.</param>
        /// <param name="showBytes">If set to <c>true</c> will return data in hexadecimal format, i.e.
        /// 7A-C5-36-B4 without the dashes. If set to <c>false</c> will return data like xRA+Ei= etc.</param>
        public static string Create(HashType hashType, string data, string sharedKey, bool showBytes)
        {
            switch(hashType)
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
                    throw new ArgumentOutOfRangeException("hashType");
            }
        }

        public static bool Verify(HashType hashType, string data, string sharedKey, bool showBytes, string hash)
        {
            return hash == Create(hashType, data, sharedKey, showBytes);
        }
 
        private static string HashData(HashAlgorithm hashAlgorithm, string data, string sharedKey, bool showBytes)
        {
            if(hashAlgorithm == null) throw new ArgumentNullException("hashAlgorithm");
            if(data == null) throw new ArgumentNullException("data");
            if(sharedKey == null) throw new ArgumentNullException("sharedKey");

            var input = Encoding.UTF8.GetBytes(data + sharedKey);
            var result = hashAlgorithm.ComputeHash(input);
            return showBytes ? BitConverter.ToString(result).Replace("-", string.Empty) : Convert.ToBase64String(result);
        }
   }
}