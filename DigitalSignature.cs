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

using System.Security.Cryptography;

namespace Effortless.Net.Encryption
{
    /// <summary>
    /// Digital sign and verify a hash using RSACryptoServiceProvider
    /// </summary>
    public class DigitalSignature
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;
        private readonly int _keySize;
        private readonly string _hashAlgorithm;

        /// <summary>
        /// Uses a key length of 2048
        /// Uses a hash algorithm of SHA256
        /// </summary>
        public DigitalSignature()
        {
            _keySize = 2048;
            _hashAlgorithm = "SHA256";
        }

        /// <summary>
        /// Create a key of a custom length.
        /// Uses a custom hash algorithm
        /// </summary>
        /// <param name="keySize">The RSACryptoServiceProvider supports key sizes from 384 bits to 16384 bits in increments of 8 bits
        /// if you have the Microsoft Enhanced Cryptographic Provider installed. It supports key sizes from 384 bits to 512 bits in
        /// increments of 8 bits if you have the Microsoft Base Cryptographic Provider installed. </param>
        /// <param name="hashAlgorithm">Specify the hash algorithm for RSAPKCS1SignatureFormatter. SHA1, SHA256, SHA384, SHA512</param>
        public DigitalSignature(int keySize, string hashAlgorithm)
        {
            _keySize = keySize;
            _hashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Generate new public and private keys
        /// </summary>
        public void AssignNewKey()
        {
            using (var rsa = new RSACryptoServiceProvider(_keySize))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        /// <summary>
        /// Loads a previously generated public key
        /// </summary>
        public void LoadPublicKey(string exponent, string modulus)
        {
            _publicKey = new RSAParameters
            {
                Exponent = Bytes.HexToByteArray(exponent),
                Modulus = Bytes.HexToByteArray(modulus)
            };
        }

        public void SavePublicKey(out string exponent, out string modulus)
        {
            exponent = Bytes.ByteArrayToHex(_publicKey.Exponent);
            modulus = Bytes.ByteArrayToHex(_publicKey.Modulus);
        }

        /// <summary>
        /// Loads a previously generated private key
        /// </summary>
        public void LoadPrivateKey(string exponent, string modulus, string p, string q, string dp, string dq, string inverseQ, string d)
        {
            _privateKey = new RSAParameters
            {
                Exponent = Bytes.HexToByteArray(exponent),
                Modulus  = Bytes.HexToByteArray(modulus),
                P        = Bytes.HexToByteArray(p),
                Q        = Bytes.HexToByteArray(q),
                DP       = Bytes.HexToByteArray(dp),
                DQ       = Bytes.HexToByteArray(dq),
                InverseQ = Bytes.HexToByteArray(inverseQ),
                D        = Bytes.HexToByteArray(d)
            };
        }

        public void SavePrivateKey(out string exponent, out string modulus, out string p, out string q, out string dp, out string dq, out string inverseQ, out string d)
        {
            exponent = _publicKey.Exponent == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.Exponent);
            modulus  = _publicKey.Modulus == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.Modulus);
            p        = _publicKey.P == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.P);
            q        = _publicKey.Q == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.Q);
            dp       = _publicKey.DP == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.DP);
            dq       = _publicKey.DQ == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.DQ);
            inverseQ = _publicKey.InverseQ == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.InverseQ);
            d        = _publicKey.D == null ? string.Empty : Bytes.ByteArrayToHex(_publicKey.D);
        }

        /// <summary>
        /// Sign a hash
        /// </summary>
        /// <param name="hashOfDataToSign">Data to sign</param>
        /// <returns>Signature</returns>
        public byte[] SignData(byte[] hashOfDataToSign)
        {
            using (var rsa = new RSACryptoServiceProvider(_keySize))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);

                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm(_hashAlgorithm);
                return rsaFormatter.CreateSignature(hashOfDataToSign);
            }
        }

        /// <summary>
        /// Verify a signature
        /// </summary>
        /// <param name="hashOfDataToSign">Data to verify</param>
        /// <param name="signature">Signature to verify</param>
        /// <returns>True if the signature matches</returns>
        public bool VerifySignature(byte[] hashOfDataToSign, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider(_keySize))
            {
                rsa.ImportParameters(_publicKey);
                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm(_hashAlgorithm);
                return rsaDeformatter.VerifySignature(hashOfDataToSign, signature);
            }
        }
    }
}