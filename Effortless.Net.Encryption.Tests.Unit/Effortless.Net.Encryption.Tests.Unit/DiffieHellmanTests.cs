using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    [TestFixture]
    public class DiffieHellmanTests
    {
        [Test]
        public void Encrypt_Decrypt()
        {
            var text = "Hello World!";

            var bob = new DiffieHellman();
            var alice = new DiffieHellman();

            // Bob uses Alice's public key to encrypt his message.
            var secretMessage = bob.Encrypt(alice.PublicKey, text);

            // Alice uses Bob's public key and IV to decrypt the secret message.
            var decryptedMessage = alice.Decrypt(bob.PublicKey, secretMessage, bob.IV);

            Assert.AreEqual(text, decryptedMessage);
        }
    }
}