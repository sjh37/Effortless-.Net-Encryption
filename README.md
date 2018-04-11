## Effortless .Net Encryption

### Project Description

Effortless .Net Encryption is a library that is written in C# and provides:

*   Rijndael encryption/decryption.
*   Hashing and Digest creation/validation.
*   Password and salt creation.

### Nuget

[https://nuget.org/packages/Effortless.Net.Encryption/](https://nuget.org/packages/Effortless.Net.Encryption/ "https://nuget.org/packages/Effortless.Net.Encryption/")

To install Effortless.Net.Encryption, run the following command in the [ Package Manager Console](http://docs.nuget.org/docs/start-here/using-the-package-manager-console)

`PM> Install-Package Effortless.Net.Encryption`

### Overview

The project is split into four main areas

*   Strings – Encryption/Decryption/Password and Salt generation
*   Hash – Creation and verification of hashes using MD5, SHA1, SHA256, SHA384, SHA512.
*   Digest – Creation and verification of digests (data + hash). Plus two handy ToString() and CreateFromString() functions which come in handy if you want to store data in a Cookie.
*   Bytes – The core of the library. This uses the Rijndael algorithm and works at the byte[] level for most functions.

### Some examples

```c#
// Creating passwords & salts
string password = Strings.CreatePassword(15, true);
string salt = Strings.CreateSalt(20);

// Encrypting/decrypting strings
byte[] key = Bytes.GenerateKey();
byte[] iv = Bytes.GenerateIV();
string encrypted = Strings.Encrypt("Secret", key, iv);
string decrypted = Strings.Decrypt(encrypted, key, iv);
Assert.AreEqual("Secret", decrypted);

// Hashes
string hash = Hash.Create(HashType.SHA512, "Hello", string.Empty, false);

// Digests
var d1 = Digest.Create(HashType.MD5, "Hello", string.Empty);
string cookieString = d1.ToString();
var d2 = Digest.CreateFromString(cookieString, string.Empty);
Assert.AreEqual(d1.Data, d2.Data);
Assert.AreEqual(d1.Hash, d2.Hash);

// Bytes
byte[] key = Bytes.GenerateKey();
byte[] iv = Bytes.GenerateIV();
var data = new byte[1024];
new RNGCryptoServiceProvider().GetBytes(data); // Random data
byte[] encrypted = Bytes.Encrypt(data, key, iv);
byte[] decrypted = Bytes.Decrypt(encrypted, key, iv);
Assert.AreEqual(data, decrypted);

// Digital Signatures
var hash = Hash.Create(HashType.SHA256, "Hello", string.Empty)
var ds = new DigitalSignature();
ds.AssignNewKey();
var signature = ds.SignData(hash);
var result = ds.VerifySignature(hash, signature);
Assert.IsTrue(result);

// Diffie Hellman
var alice = new DiffieHellman();
var bob = new DiffieHellman();
// Bob uses Alice's public key to encrypt his message.
var secretMessage = bob.Encrypt(alice, "Hello");
// Alice uses Bob's public key and IV to decrypt the secret message.
var decryptedMessage = alice.Decrypt(bob, secretMessage);
Assert.AreEqual("Hello", decryptedMessage);
```
