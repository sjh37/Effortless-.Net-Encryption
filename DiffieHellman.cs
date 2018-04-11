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