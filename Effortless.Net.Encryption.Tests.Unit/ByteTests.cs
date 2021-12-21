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

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Bytes.ResetPaddingAndCipherModes();

            var path = Path.GetTempPath();
            _fileEncryptedData = Path.Combine(path, "testEncrypted.txt");
            _filePlainData = Path.Combine(path, "testPlain.txt");
            _plainData = GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla auctor, justo quis rhoncus hendrerit, lacus ligula lobortis ipsum, et semper justo lorem ut tellus. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur scelerisque nisl et lacus pulvinar malesuada. In hac habitasse platea dictumst. Curabitur est metus, posuere quis pulvinar a, congue nec neque. Sed at mi vitae leo condimentum blandit. Mauris in tortor eu risus pellentesque molestie. Aliquam at leo eget erat volutpat ultricies in in purus. Quisque elit sapien, accumsan vitae sagittis ac, faucibus congue neque.");
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
        public void Encrypt_4k_10_times_using_all_padding_and_cypher_modes()
        {
            foreach (var paddingMode in (PaddingMode[]) Enum.GetValues(typeof(PaddingMode)))
            {
                if (paddingMode == PaddingMode.None)
                    continue;

                foreach (var cipherMode in (CipherMode[]) Enum.GetValues(typeof(CipherMode)))
                {
                    if (!Bytes.SetPaddingAndCipherModes(paddingMode, cipherMode))
                        continue; // invalid padding/cipher mode

                    Console.WriteLine("Padding Mode {0} CipherMode Mode {1}", paddingMode, cipherMode);

                    foreach (var keySize in (Bytes.KeySize[]) Enum.GetValues(typeof(Bytes.KeySize)))
                    {
                        if (keySize == Bytes.KeySize.Default)
                            continue;

                        Console.WriteLine("    KeySize {0}", keySize);
                        var key = Bytes.GenerateKey(keySize);
                        var iv = Bytes.GenerateIV(keySize);
                        var random = new Random();

                        for (var n = 0; n < 10; n++)
                        {
                            var size = random.Next(4096) + 1;
                            var data = new byte[size];
                            Bytes.GetRandomBytes(data);

                            var encrypted = Bytes.Encrypt(data, key, iv, keySize);
                            var decrypted = Bytes.Decrypt(encrypted, key, iv, keySize);
                            Assert.AreEqual(data, decrypted);
                        }
                    }
                }
            }
            Bytes.ResetPaddingAndCipherModes();
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
            foreach (var paddingMode in (PaddingMode[]) Enum.GetValues(typeof(PaddingMode)))
            {
                if (paddingMode == PaddingMode.None)
                    continue;

                foreach (var cipherMode in (CipherMode[]) Enum.GetValues(typeof(CipherMode)))
                {
                    if (!Bytes.SetPaddingAndCipherModes(paddingMode, cipherMode))
                        continue; // invalid padding/cipher mode

                    Console.WriteLine("Padding Mode {0} CipherMode Mode {1}", paddingMode, cipherMode);
                    foreach (var keySize in (Bytes.KeySize[]) Enum.GetValues(typeof(Bytes.KeySize)))
                    {

                        Console.WriteLine("    KeySize {0}", keySize);

                        var rm = new RijndaelManaged
                        {
                            KeySize = (int) keySize,
                            BlockSize = 128,
                            Padding = paddingMode,
                            Mode = cipherMode
                        };

                        // Encrypt file
                        using (var fsIn = new FileStream(_filePlainData, FileMode.Open, FileAccess.Read))
                        {
                            Bytes.Encrypt(fsIn, _fileEncryptedData, rm);
                        }

                        // Decrypt file data
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var fsIn = new FileStream(_fileEncryptedData, FileMode.Open, FileAccess.Read))
                            {
                                Bytes.Decrypt(fsIn, memoryStream, rm);
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
            foreach (var keySize in (Bytes.KeySize[]) Enum.GetValues(typeof(Bytes.KeySize)))
            {
                Console.WriteLine("KeySize {0}", keySize);

                var key = Bytes.GenerateKey(keySize);
                var iv = Bytes.GenerateIV(keySize);

                var data = new byte[1024];
                Bytes.GetRandomBytes(data);

                var encrypted = Bytes.Encrypt(data, key, iv, keySize);
                var decrypted = Bytes.Decrypt(encrypted, key, iv, keySize);
                Assert.AreEqual(data, decrypted);
            }
        }

        [Test]
        [TestCase(1)]
        [TestCase(1000)]
        [TestCase(10000)]
        public void Generate_key_with_password_and_salt_iv_encrypt_decrypt_128(int iterationCount)
        {
            foreach (var keySize in (Bytes.KeySize[]) Enum.GetValues(typeof(Bytes.KeySize)))
            {
                if (keySize == Bytes.KeySize.Default)
                    continue;
                Console.WriteLine("KeySize {0}", keySize);
                var key = Bytes.GenerateKey("password", "saltsaltsalt", keySize, iterationCount);
                var iv = Bytes.GenerateIV();

                var data = new byte[1024];
                Bytes.GetRandomBytes(data);

                var encrypted = Bytes.Encrypt(data, key, iv);
                var decrypted = Bytes.Decrypt(encrypted, key, iv);
                Assert.AreEqual(data, decrypted);
            }
        }

        [Test]
        [TestCase(1)]
        [TestCase(1000)]
        [TestCase(10000)]
        public void Generate_key_with_password_and_salt_iv_encrypt_decrypt_192(int iterationCount)
        {
            foreach (var keySize in (Bytes.KeySize[]) Enum.GetValues(typeof(Bytes.KeySize)))
            {
                if (keySize == Bytes.KeySize.Default)
                    continue;
                Console.WriteLine("KeySize {0}", keySize);
                var key = Bytes.GenerateKey("password", "saltsaltsalt", keySize, iterationCount);
                var iv = Bytes.GenerateIV();

                var data = new byte[1024];
                Bytes.GetRandomBytes(data);

                var encrypted = Bytes.Encrypt(data, key, iv);
                var decrypted = Bytes.Decrypt(encrypted, key, iv);
                Assert.AreEqual(data, decrypted);
            }
        }

        [Test]
        [TestCase(1)]
        [TestCase(1000)]
        [TestCase(10000)]
        public void Generate_key_with_password_and_salt_iv_encrypt_decrypt_256(int iterationCount)
        {
            foreach (var keySize in (Bytes.KeySize[]) Enum.GetValues(typeof(Bytes.KeySize)))
            {
                if (keySize == Bytes.KeySize.Default)
                    continue;
                Console.WriteLine("KeySize {0}", keySize);
                var key = Bytes.GenerateKey("password", "saltsaltsalt", keySize, iterationCount);
                var iv = Bytes.GenerateIV();

                var data = new byte[1024];
                Bytes.GetRandomBytes(data);

                var encrypted = Bytes.Encrypt(data, key, iv);
                var decrypted = Bytes.Decrypt(encrypted, key, iv);
                Assert.AreEqual(data, decrypted);
            }
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