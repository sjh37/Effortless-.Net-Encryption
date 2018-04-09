using System;
using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    [TestFixture]
    public class DigitalSignatureTests
    {
        private byte[] _hash;

        [TestFixtureSetUp]
        public void SetUp()
        {
            _hash = Hash.Create(HashType.SHA256, "Hello world", string.Empty);
        }

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
            Assert.IsTrue(result);
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

            byte[] hash;
            switch (hashAlgorithm)
            {
                case "SHA1":
                    hash = Hash.Create(HashType.SHA1, "Hello world", string.Empty);
                    break;
                case "SHA256":
                    hash = Hash.Create(HashType.SHA256, "Hello world", string.Empty);
                    break;
                case "SHA384":
                    hash = Hash.Create(HashType.SHA384, "Hello world", string.Empty);
                    break;
                case "SHA512":
                    hash = Hash.Create(HashType.SHA512, "Hello world", string.Empty);
                    break;
                default:
                    throw new ArgumentException("hashAlgorithm");
            }
            var signature = ds.SignData(hash);
            var result = ds.VerifySignature(hash, signature);
            Assert.IsTrue(result);
        }

        [Test]
        public void SavedPublicAndPrivateKeysMatch()
        {
            var ds = new DigitalSignature();
            ds.AssignNewKey();

            ds.SavePublicKey(out var exponent1, out var modulus1);
            ds.SavePrivateKey(out var exponent2, out var modulus2, out var p, out var q, out var dp, out var dq, out var inverseQ, out var d);

            Assert.AreEqual(exponent1, exponent2);
            Assert.AreEqual(modulus1, modulus2);
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
            Assert.IsTrue(result1);


            var sut = new DigitalSignature();
            sut.LoadPublicKey(exponent1, modulus1);
            sut.LoadPrivateKey(exponent2, modulus2, p, q, dp, dq, inverseQ, d);

            var signature2 = ds.SignData(_hash);
            var result2 = ds.VerifySignature(_hash, signature2);
            Assert.IsTrue(result2);

            Assert.AreEqual(signature1, signature2);
        }
    }
}