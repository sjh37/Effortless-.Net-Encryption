using System;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    [TestFixture]
    public class ByteTests
    {
        [Test]
        public void Byte1()
        {
            byte[] key = Bytes.GenerateKey();
            byte[] iv = Bytes.GenerateIV();

            var rng = new RNGCryptoServiceProvider();
            var data = new byte[1024];
            rng.GetBytes(data);

            byte[] encrypted = Bytes.Encrypt(data, key, iv);
            byte[] decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        public void Byte2()
        {
            byte[] key = Bytes.GenerateKey("password", "saltsaltsalt", Bytes.KeySize.Size128);
            byte[] iv = Bytes.GenerateIV();

            var rng = new RNGCryptoServiceProvider();
            var data = new byte[1024];
            rng.GetBytes(data);

            byte[] encrypted = Bytes.Encrypt(data, key, iv);
            byte[] decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        public void Byte3()
        {
            byte[] key = Bytes.GenerateKey("password", "saltsaltsalt", Bytes.KeySize.Size192);
            byte[] iv = Bytes.GenerateIV();

            var rng = new RNGCryptoServiceProvider();
            var data = new byte[1024];
            rng.GetBytes(data);

            byte[] encrypted = Bytes.Encrypt(data, key, iv);
            byte[] decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        public void Byte4()
        {
            byte[] key = Bytes.GenerateKey("password", "saltsaltsalt", Bytes.KeySize.Size256);
            byte[] iv = Bytes.GenerateIV();

            var rng = new RNGCryptoServiceProvider();
            var data = new byte[1024];
            rng.GetBytes(data);

            byte[] encrypted = Bytes.Encrypt(data, key, iv);
            byte[] decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        public void ByteLong()
        {
            byte[] key = Bytes.GenerateKey();
            byte[] iv = Bytes.GenerateIV();
            var random = new Random();

            var rng = new RNGCryptoServiceProvider();
            for (int n = 0; n < 100; n++)
            {
                int size = random.Next(32768)+1;
                var data = new byte[size];
                rng.GetBytes(data);

                byte[] encrypted = Bytes.Encrypt(data, key, iv);
                byte[] decrypted = Bytes.Decrypt(encrypted, key, iv);
                Assert.AreEqual(data, decrypted);
            }
        }
    }
}