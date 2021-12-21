using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    [TestFixture]
    public class HashTests
    {
        [Test]
        [TestCase(true, HashType.MD5, "63602C271DFB9E8A2B16823A5DC5020E")]
        [TestCase(true, HashType.SHA1, "6FD75D8D3D3A7FB244F04178AA50C8AF2180BA72")]
        [TestCase(true, HashType.SHA256, "F7AAE2D999881387B8362976AD878D041527F78F7EFF7D1EAFA1A6212A2A4061")]
        [TestCase(true, HashType.SHA384, "B78E547A75A256B7902F05378D452AB6C8192D48232E312B466E40E5ED9BE1A5B77053251C5D0177EFF1DDC2A6DE9B1E")]
        [TestCase(true, HashType.SHA512, "A300C834A06AA8935B27991C2F3D044009AC1952E0B51845DD8AE2178F778C82F012C3A343266C41A493A8D16966C25A4F88E2A8FBEAE6AD8D5F0AA6FE29665A")]
        [TestCase(false, HashType.MD5, "Y2AsJx37noorFoI6XcUCDg==")]
        [TestCase(false, HashType.SHA1, "b9ddjT06f7JE8EF4qlDIryGAunI=")]
        [TestCase(false, HashType.SHA256, "96ri2ZmIE4e4Nil2rYeNBBUn949+/30er6GmISoqQGE=")]
        [TestCase(false, HashType.SHA384, "t45UenWiVreQLwU3jUUqtsgZLUgjLjErRm5A5e2b4aW3cFMlHF0Bd+/x3cKm3pse")]
        [TestCase(false, HashType.SHA512, "owDINKBqqJNbJ5kcLz0EQAmsGVLgtRhF3YriF493jILwEsOjQyZsQaSTqNFpZsJaT4jiqPvq5q2NXwqm/ilmWg==")]
        public void Create(bool showBytes, HashType hashType, string result)
        {
            const string data = "Hello";
            const string sharedKey = "key";
            var hash = Hash.Create(hashType, data, sharedKey, showBytes);
            Assert.AreEqual(result, hash);
            Assert.IsTrue(Hash.Verify(hashType, data, sharedKey, showBytes, hash));
            Assert.IsFalse(Hash.Verify(hashType, data, "unknownKey", showBytes, hash));
        }

        [Test]
        [TestCase(true, true, "", "")]
        [TestCase(true, false, "", "")]
        [TestCase(false, true, "", "")]
        [TestCase(false, false, "", "")]
        [TestCase(true, true, "key", "Key")]
        [TestCase(true, false, "key", "Key")]
        [TestCase(false, true, "key", "Key")]
        [TestCase(false, false, "key", "Key")]
        public void CreateHashInLoop(bool allowPunctuation, bool showBytes, string key1, string key2)
        {
            const int passLen = 10;
            for (var n = 0; n < 100; n++)
            {
                var password = Strings.CreatePassword(passLen, allowPunctuation);
                Assert.IsTrue(password.Length == passLen);

                var hash1 = Hash.Create(HashType.MD5, password, key1, showBytes);
                var hash2 = Hash.Create(HashType.MD5, password, key2, showBytes);

                Assert.IsTrue(Hash.Verify(HashType.MD5, password, key1, showBytes, hash1));
                Assert.IsTrue(Hash.Verify(HashType.MD5, password, key2, showBytes, hash2));

                if (key1 == key2)
                    Assert.AreEqual(hash1, hash2);
                else
                    Assert.AreNotEqual(hash1, hash2);
            }
        }

        [Test]
        [TestCase(true, HashType.MD5, "ED8DEEF5BA6E0731D0C01EE7C4BAFC36")]
        [TestCase(true, HashType.SHA1, "D2EFCBBA102ED3339947E85F4141EB08926E40E9")]
        [TestCase(true, HashType.SHA256, "A07E4F7343246C82B26F32E56F85418D518D8B2F2DAE77F1D56FE7AF50DB97AF")]
        [TestCase(true, HashType.SHA384, "7428EA564921C0E1F5C927D4E72F0C4A01D9A7AC3D7A204C5A9D3040A88249953090D9763FEDA173FEE3FA71F75E27DD")]
        [TestCase(true, HashType.SHA512, "2C5F15C7829564C32AF70D9AEE7389BDE5D0544534010C9058D0D7A0CC7DE49656E0674041A0907B80B1B05E18B459B5428AE8EE0F43A680F0922EE3D00E6A14")]
        [TestCase(false, HashType.MD5, "7Y3u9bpuBzHQwB7nxLr8Ng==")]
        [TestCase(false, HashType.SHA1, "0u/LuhAu0zOZR+hfQUHrCJJuQOk=")]
        [TestCase(false, HashType.SHA256, "oH5Pc0MkbIKybzLlb4VBjVGNiy8trnfx1W/nr1Dbl68=")]
        [TestCase(false, HashType.SHA384, "dCjqVkkhwOH1ySfU5y8MSgHZp6w9eiBMWp0wQKiCSZUwkNl2P+2hc/7j+nH3Xifd")]
        [TestCase(false, HashType.SHA512, "LF8Vx4KVZMMq9w2a7nOJveXQVEU0AQyQWNDXoMx95JZW4GdAQaCQe4CxsF4YtFm1Qoro7g9DpoDwki7j0A5qFA==")]
        public void CreateWithNoKey(bool showBytes, HashType hashType, string result)
        {
            const string data = "Hello";
            var hash = Hash.Create(hashType, data, string.Empty, showBytes);
            Assert.AreEqual(result, hash);
            Assert.IsTrue(Hash.Verify(hashType, data, string.Empty, showBytes, hash));
            Assert.IsFalse(Hash.Verify(hashType, data, "unknownKey", showBytes, hash));
        }

        [Test]
        public void MultiThreaded()
        {
            var hashAlgorithm = SHA512.Create();
            var bytes = Encoding.Default.GetBytes("Hello world");

            var expected = Convert.ToBase64String(hashAlgorithm.ComputeHash(bytes));
            Console.WriteLine("Expected");
            Console.WriteLine(expected);
            Console.WriteLine();

            var hashLock = new object();
            Parallel.For(0, 1000, ignored =>
            {
                byte[] hash;
                lock (hashLock)
                {
                    // Lock only for shortest duration
                    hash = hashAlgorithm.ComputeHash(bytes);
                }
                var base64 = Convert.ToBase64String(hash);
                Assert.AreEqual(expected, base64);
            });
        }

        [Test]
        public void MultiThreaded_v2()
        {
            var bytes = Encoding.Default.GetBytes("Hello world");

            var expected = Convert.ToBase64String(SHA512.Create().ComputeHash(bytes));
            Console.WriteLine("Expected");
            Console.WriteLine(expected);
            Console.WriteLine();

            Parallel.For(0, 1000, ignored =>
            {
                var base64 = Convert.ToBase64String(SHA512.Create().ComputeHash(bytes));
                Assert.AreEqual(expected, base64);
            });
        }
    }
}