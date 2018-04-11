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
        public byte[] IV => _aes.IV;

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

        public byte[] Encrypt(byte[] publicKey, string secretMessage)
        {
            byte[] encryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = _diffieHellman.DeriveKeyMaterial(key); // "Common secret"

            _aes.Key = derivedKey;

            using (var cipherText = new MemoryStream())
            {
                using (var cs = new CryptoStream(cipherText, _aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    var ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    cs.Close();
                }

                encryptedMessage = cipherText.ToArray();
            }

            return encryptedMessage;
        }

        public string Decrypt(byte[] publicKey, byte[] encryptedMessage, byte[] iv)
        {
            string decryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = _diffieHellman.DeriveKeyMaterial(key);

            _aes.Key = derivedKey;
            _aes.IV = iv;

            using (var plainText = new MemoryStream())
            {
                using (var cs = new CryptoStream(plainText, _aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                    cs.Close();
                }

                decryptedMessage = Encoding.UTF8.GetString(plainText.ToArray());
            }

            return decryptedMessage;
        }
    }
}