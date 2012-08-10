namespace Effortless.Net.Encryption.Tests.Unit
{
    using System;
    using System.Collections.Generic;
    using NUnit.Framework;

    [TestFixture]
    public class StringsTest
    {
        [Test]
        [TestCase(true)]
        [TestCase(false)]
        public void Create_password(bool allowPunctuation)
        {
            const int passLen = 10;
            var list = new List<string>();
            for(int n = 0; n < 100; n++)
            {
                string password = Strings.CreatePassword(passLen, allowPunctuation);
                Assert.AreEqual(passLen, password.Length);

                foreach(char c in password)
                {
                    if(allowPunctuation)
                        Assert.IsTrue(Char.IsLetterOrDigit(c) || Char.IsPunctuation(c));
                    else
                        Assert.IsTrue(Char.IsLetterOrDigit(c));
                }

                Assert.IsFalse(list.Contains(password));
                list.Add(password);
            }
        }

        [Test]
        [TestCase(1, true)]
        [TestCase(1, false)]
        [TestCase(10, true)]
        [TestCase(10, false)]
        [TestCase(100, true)]
        [TestCase(100, false)]
        [TestCase(1000, true)]
        [TestCase(1000, false)]
        [TestCase(10000, true)]
        [TestCase(10000, false)]
        public void Create_long_password(int size, bool allowPunctuation)
        {
            // Check for a long password, so it causes multiple CreateSaltsFull() function calls
            string s = Strings.CreatePassword(size, allowPunctuation);
            Assert.AreEqual(size, s.Length);
        }

        [Test]
        public void Create_salt()
        {
            const int saltLen = 30;
            var list = new List<string>();
            for(int n = 0; n < 100; n++)
            {
                string salt = Strings.CreateSalt(saltLen);
                Assert.IsTrue(salt.Length == saltLen);

                Assert.IsFalse(list.Contains(salt));
                list.Add(salt);
            }
        }

        [Test]
        [TestCase(@"$L;R*gM0\3+%@!#pLR4!@b#ryu'E+Wre_6r^i,b?2-mQ hu|^8ZnQ[_rw._i6%C")]
        [TestCase("Hello world")]
        [TestCase("This is another test")]
        public void Encrypt_decrypt_using_key_iv(string data)
        {
            byte[] key = Bytes.GenerateKey();
            byte[] iv = Bytes.GenerateIV();

            string encrypted = Strings.Encrypt(data, key, iv);
            string decrypted = Strings.Decrypt(encrypted, key, iv);

            Assert.AreEqual(data, decrypted);
        }

        [Test]
        [TestCase(128)]
        [TestCase(192)]
        [TestCase(256)]
        public void Encrypt_decrypt_using_different_key_sizes(Bytes.KeySize keySize)
        {
            const string password = "Hello world";
            const string salt = "saltsaltsalt";
            string iv = string.Empty.PadLeft(32, '#');
            const string original = "This is another test";

            string encrypted = Strings.Encrypt(original, password, salt, iv, keySize);
            string decrypted = Strings.Decrypt(encrypted, password, salt, iv, keySize);
            Assert.AreEqual(original, decrypted);
        }

        [Test]
        public void Encrypt_decrypt_using_a_very_long_string()
        {
            var key = Bytes.GenerateKey();
            var iv = Bytes.GenerateIV();
            var random = new Random();

            for(var n = 0; n < 100; n++)
            {
                var size = random.Next(4096) + 1;
                var data = Strings.CreateSalt(size);
                var encrypted = Strings.Encrypt(data, key, iv);
                var decrypted = Strings.Decrypt(encrypted, key, iv);
                Assert.AreEqual(data, decrypted);
            }
        }
    }
}