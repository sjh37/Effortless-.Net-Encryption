using System;
using System.IO;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    [TestFixture]
    public class ByteTests
    {
        [SetUp]
        public void SetUp()
        {
            File.WriteAllBytes(_filePlainData, _plainData);
            DeleteOutputFile();
        }

        [TearDown]
        public void TearDown()
        {
            DeleteOutputFile();
        }

        private byte[] _plainData;
        private string _filePlainData;
        private string _fileEncryptedData;
        private RijndaelManaged _rijndaelManaged;

        [TestFixtureSetUp]
        public void TextFixtureSetUp()
        {
            var path = Path.GetTempPath();
            _fileEncryptedData = Path.Combine(path, "testEncrypted.txt");
            _filePlainData = Path.Combine(path, "testPlain.txt");
            _plainData = GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla auctor, justo quis rhoncus hendrerit, lacus ligula lobortis ipsum, et semper justo lorem ut tellus. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur scelerisque nisl et lacus pulvinar malesuada. In hac habitasse platea dictumst. Curabitur est metus, posuere quis pulvinar a, congue nec neque. Sed at mi vitae leo condimentum blandit. Mauris in tortor eu risus pellentesque molestie. Aliquam at leo eget erat volutpat ultricies in in purus. Quisque elit sapien, accumsan vitae sagittis ac, faucibus congue neque.");

            _rijndaelManaged = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 256,
                Padding = PaddingMode.ISO10126,
                Mode = CipherMode.CBC
            };
        }

        private static byte[] GetBytes(string str)
        {
            var bytes = new byte[str.Length * sizeof(char)];
            Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        private void DeleteOutputFile()
        {
            if (File.Exists(_fileEncryptedData))
                File.Delete(_fileEncryptedData);
        }

        [Test]
        public void Encrypt_32k_100_times()
        {
            var key = Bytes.GenerateKey();
            var iv = Bytes.GenerateIV();
            var random = new Random();

            for (var n = 0; n < 100; n++)
            {
                var size = random.Next(32768) + 1;
                var data = new byte[size];
                Bytes.GetRandomBytes(data);

                var encrypted = Bytes.Encrypt(data, key, iv);
                var decrypted = Bytes.Decrypt(encrypted, key, iv);
                Assert.AreEqual(data, decrypted);
            }
        }

        [Test]
        public void Encrypt_Decrypt_file_to_file_using_key_iv()
        {
            var key = Bytes.GenerateKey();
            var iv = Bytes.GenerateIV();

            Bytes.Encrypt(_filePlainData, _fileEncryptedData, key, iv);
            Bytes.Decrypt(_fileEncryptedData, _filePlainData, key, iv);

            var decryptedData = File.ReadAllBytes(_filePlainData);
            Assert.AreEqual(_plainData.Length, decryptedData.Length);

            for (var i = 0; i < _plainData.Length; i++)
                Assert.AreEqual(_plainData[i], decryptedData[i]);
        }

        [Test]
        public void Encrypt_Decrypt_file_to_file_with_generated_key_iv()
        {
            Bytes.Encrypt(_filePlainData, _fileEncryptedData, out string key, out string iv);
            Bytes.Decrypt(_fileEncryptedData, _filePlainData, key, iv);

            var decryptedData = File.ReadAllBytes(_filePlainData);
            Assert.AreEqual(_plainData.Length, decryptedData.Length);

            for (var i = 0; i < _plainData.Length; i++)
                Assert.AreEqual(_plainData[i], decryptedData[i]);
        }

        [Test]
        public void Encrypt_Decrypt_stream_to_file_using_own_Rijndael_algorithm()
        {
            // Encrypt file
            using (var fsIn = new FileStream(_filePlainData, FileMode.Open, FileAccess.Read))
            {
                Bytes.Encrypt(fsIn, _fileEncryptedData, _rijndaelManaged);
            }

            // Decrypt file data
            using (var memoryStream = new MemoryStream())
            {
                using (var fsIn = new FileStream(_fileEncryptedData, FileMode.Open, FileAccess.Read))
                {
                    Bytes.Decrypt(fsIn, memoryStream, _rijndaelManaged);
                }

                // Verify
                memoryStream.Seek(0, SeekOrigin.Begin);
                Assert.AreEqual(_plainData.Length, memoryStream.Length);

                foreach (var expected in _plainData)
                {
                    var b = memoryStream.ReadByte();
                    Assert.AreEqual(expected, b);
                }
            }
        }

        [Test]
        public void Encrypt_Decrypt_stream_to_file_with_generated_key_iv()
        {
            // Encrypt file
            string key, iv;
            using (var fsIn = new FileStream(_filePlainData, FileMode.Open, FileAccess.Read))
            {
                Bytes.Encrypt(fsIn, _fileEncryptedData, out key, out iv);
            }

            // Decrypt file data
            using (var memoryStream = new MemoryStream())
            {
                Bytes.Decrypt(_fileEncryptedData, memoryStream, key, iv);

                // Verify
                memoryStream.Seek(0, SeekOrigin.Begin);
                Assert.AreEqual(_plainData.Length, memoryStream.Length);

                foreach (var expected in _plainData)
                {
                    var b = memoryStream.ReadByte();
                    Assert.AreEqual(expected, b);
                }
            }
        }

        [Test]
        public void Generate_key_iv_encrypt_decrypt()
        {
            var key = Bytes.GenerateKey();
            var iv = Bytes.GenerateIV();

            var data = new byte[1024];
            Bytes.GetRandomBytes(data);

            var encrypted = Bytes.Encrypt(data, key, iv);
            var decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        [TestCase(1)]
        [TestCase(1000)]
        [TestCase(10000)]
        public void Generate_key_with_password_and_salt_iv_encrypt_decrypt_128(int iterationCount)
        {
            var key = Bytes.GenerateKey("password", "saltsaltsalt", Bytes.KeySize.Size128, iterationCount);
            var iv = Bytes.GenerateIV();

            var data = new byte[1024];
            Bytes.GetRandomBytes(data);

            var encrypted = Bytes.Encrypt(data, key, iv);
            var decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        [TestCase(1)]
        [TestCase(1000)]
        [TestCase(10000)]
        public void Generate_key_with_password_and_salt_iv_encrypt_decrypt_192(int iterationCount)
        {
            var key = Bytes.GenerateKey("password", "saltsaltsalt", Bytes.KeySize.Size192, iterationCount);
            var iv = Bytes.GenerateIV();

            var data = new byte[1024];
            Bytes.GetRandomBytes(data);

            var encrypted = Bytes.Encrypt(data, key, iv);
            var decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        [TestCase(1)]
        [TestCase(1000)]
        [TestCase(10000)]
        public void Generate_key_with_password_and_salt_iv_encrypt_decrypt_256(int iterationCount)
        {
            var key = Bytes.GenerateKey("password", "saltsaltsalt", Bytes.KeySize.Size256, iterationCount);
            var iv = Bytes.GenerateIV();

            var data = new byte[1024];
            Bytes.GetRandomBytes(data);

            var encrypted = Bytes.Encrypt(data, key, iv);
            var decrypted = Bytes.Decrypt(encrypted, key, iv);
            Assert.AreEqual(data, decrypted);
        }

        [Test]
        [TestCase(0)]
        [TestCase(1)]
        [TestCase(2)]
        [TestCase(4)]
        [TestCase(10)]
        [TestCase(11)]
        [TestCase(100)]
        [TestCase(101)]
        [TestCase(1000)]
        [TestCase(1001)]
        public void ByteArrayToHex_HexToByteArray(int numChars)
        {
            var data = new byte[numChars];
            Bytes.GetRandomBytes(data);

            var hexString = Bytes.ByteArrayToHex(data);
            var result = Bytes.HexToByteArray(hexString);
            Assert.AreEqual(data, result);
        }

        //private static string GetString(byte[] bytes)
        //{
        //    var chars = new char[bytes.Length / sizeof(char)];
        //    Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
        //    return new string(chars);
        //}
    }
}