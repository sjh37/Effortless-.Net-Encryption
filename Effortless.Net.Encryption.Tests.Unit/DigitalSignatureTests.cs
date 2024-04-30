using System;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace Effortless.Net.Encryption.Tests.Unit;

[TestFixture]
public class DigitalSignatureTests
{
    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _hash = Hash.Create(HashType.SHA256, "Hello world", string.Empty);
    }

    private byte[] _hash;

    [Test]
    [TestCase(512)]
    [TestCase(1024)]
    [TestCase(2048)]
    [TestCase(4096)]
    //[TestCase(8192)] // Slow
    //[TestCase(16384)] // Very slow
    public void KeySizeTests(int keySize)
    {
        var ds = new DigitalSignature(keySize, "SHA256");
        ds.AssignNewKey();

        var signature = ds.SignData(_hash);
        var result = ds.VerifySignature(_hash, signature);
        ClassicAssert.IsTrue(result);
    }

    [Test]
    [TestCase(1024, "SHA1")]
    [TestCase(1024, "SHA256")]
    [TestCase(1024, "SHA384")]
    [TestCase(1024, "SHA512")]
    [TestCase(2048, "SHA1")]
    [TestCase(2048, "SHA256")]
    [TestCase(2048, "SHA384")]
    [TestCase(2048, "SHA512")]
    public void HashAlgorithmTests(int keySize, string hashAlgorithm)
    {
        var ds = new DigitalSignature(keySize, hashAlgorithm);
        ds.AssignNewKey();

        var hash = hashAlgorithm switch
        {
            "SHA1" => Hash.Create(HashType.SHA1, "Hello world", string.Empty),
            "SHA256" => Hash.Create(HashType.SHA256, "Hello world", string.Empty),
            "SHA384" => Hash.Create(HashType.SHA384, "Hello world", string.Empty),
            "SHA512" => Hash.Create(HashType.SHA512, "Hello world", string.Empty),
            _ => throw new ArgumentException("hashAlgorithm")
        };
        var signature = ds.SignData(hash);
        var result = ds.VerifySignature(hash, signature);
        ClassicAssert.IsTrue(result);
    }

    [Test]
    public void SavedPublicAndPrivateKeysMatch()
    {
        var ds = new DigitalSignature();
        ds.AssignNewKey();

        ds.SavePublicKey(out var exponent1, out var modulus1);
        ds.SavePrivateKey(out var exponent2, out var modulus2, out _, out _, out _, out _, out _, out _);

        ClassicAssert.AreEqual(exponent1, exponent2);
        ClassicAssert.AreEqual(modulus1, modulus2);
    }

    [Test]
    public void SaveAndLoadKeys()
    {
        var ds = new DigitalSignature();
        ds.AssignNewKey();

        ds.SavePublicKey(out var exponent1, out var modulus1);
        ds.SavePrivateKey(out var exponent2, out var modulus2, out var p, out var q, out var dp, out var dq, out var inverseQ, out var d);

        var signature1 = ds.SignData(_hash);
        var result1 = ds.VerifySignature(_hash, signature1);
        ClassicAssert.IsTrue(result1);


        var sut = new DigitalSignature();
        sut.LoadPublicKey(exponent1, modulus1);
        sut.LoadPrivateKey(exponent2, modulus2, p, q, dp, dq, inverseQ, d);

        var signature2 = ds.SignData(_hash);
        var result2 = ds.VerifySignature(_hash, signature2);
        ClassicAssert.IsTrue(result2);

        ClassicAssert.AreEqual(signature1, signature2);
    }
}