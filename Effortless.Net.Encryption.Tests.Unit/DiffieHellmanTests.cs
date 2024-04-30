using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace Effortless.Net.Encryption.Tests.Unit;

[TestFixture]
public class DiffieHellmanTests
{
    [Test]
    public void Encrypt_Decrypt()
    {
        const string text = "Hello World!";

        var alice = new DiffieHellman();
        var bob = new DiffieHellman();

        // Bob uses Alice's public key to encrypt his message.
        var secretMessage = bob.Encrypt(alice, text);

        // Alice uses Bob's public key and IV to decrypt the secret message.
        var decryptedMessage = alice.Decrypt(bob, secretMessage);
        ClassicAssert.AreEqual(text, decryptedMessage);
    }

    [Test]
    public void MultipleTests()
    {
        const string text = "Hello World!";

        var alice = new DiffieHellman();
        var bob = new DiffieHellman();

        var secretMessageA = alice.Encrypt(bob, text);
        var secretMessage1 = bob.Encrypt(alice, text);
        var decryptedMessage = alice.Decrypt(bob, secretMessage1);
        var secretMessageB = alice.Encrypt(bob, text);
        ClassicAssert.AreEqual(text, decryptedMessage);
        ClassicAssert.AreEqual(secretMessageA, secretMessageB);

        // See if its repeatable due to IV being replaced by previous decryption
        var secretMessage2 = bob.Encrypt(alice, text);
        decryptedMessage = alice.Decrypt(bob, secretMessage2);
        ClassicAssert.AreEqual(text, decryptedMessage);

        // Should be the same if nothing has changed
        ClassicAssert.AreEqual(secretMessage1, secretMessage2);
    }
}