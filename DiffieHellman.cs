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

using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Effortless.Net.Encryption
{
    public sealed class DiffieHellman
    {
        private readonly Aes _aes;
        private readonly ECDiffieHellmanCng _diffieHellman;
        public byte[] PublicKey { get; }

        public DiffieHellman()
        {
            _aes = new AesCryptoServiceProvider();

            _diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };

            // This is the public key we will send to the other party
            PublicKey = _diffieHellman.PublicKey.ToByteArray();
        }

        public byte[] Encrypt(DiffieHellman otherPerson, string secretMessage)
        {
            // Common secret created by Diffie Hellman
            _aes.Key = _diffieHellman.DeriveKeyMaterial(CngKey.Import(otherPerson.PublicKey, CngKeyBlobFormat.EccPublicBlob));

            using (var cipherText = new MemoryStream())
            {
                using (var cs = new CryptoStream(cipherText, _aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    var ciphertextMessage = Encoding.Unicode.GetBytes(secretMessage);
                    cs.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    cs.Close();
                }

                return cipherText.ToArray();
            }
        }

        public string Decrypt(DiffieHellman otherPerson, byte[] encryptedMessage)
        {
            // Common secret created by Diffie Hellman
            _aes.Key = _diffieHellman.DeriveKeyMaterial(CngKey.Import(otherPerson.PublicKey, CngKeyBlobFormat.EccPublicBlob));
            var backupIV = _aes.IV;
            _aes.IV = otherPerson._aes.IV;

            using (var plainText = new MemoryStream())
            {
                using (var cs = new CryptoStream(plainText, _aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                    cs.Close();
                }

                _aes.IV = backupIV;

                return Encoding.Unicode.GetString(plainText.ToArray());
            }
        }
    }
}