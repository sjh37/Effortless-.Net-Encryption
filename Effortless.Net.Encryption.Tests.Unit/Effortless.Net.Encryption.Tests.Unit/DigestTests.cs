using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    public class DigestTests
    {
        [Test]
        [TestCase(HashType.MD5, "", "ED8DEEF5BA6E0731D0C01EE7C4BAFC36")]
        [TestCase(HashType.SHA1, "", "D2EFCBBA102ED3339947E85F4141EB08926E40E9")]
        [TestCase(HashType.SHA256, "", "A07E4F7343246C82B26F32E56F85418D518D8B2F2DAE77F1D56FE7AF50DB97AF")]
        [TestCase(HashType.SHA384, "", "7428EA564921C0E1F5C927D4E72F0C4A01D9A7AC3D7A204C5A9D3040A88249953090D9763FEDA173FEE3FA71F75E27DD")]
        [TestCase(HashType.SHA512, "", "2C5F15C7829564C32AF70D9AEE7389BDE5D0544534010C9058D0D7A0CC7DE49656E0674041A0907B80B1B05E18B459B5428AE8EE0F43A680F0922EE3D00E6A14")]
        [TestCase(HashType.MD5, "key", "63602C271DFB9E8A2B16823A5DC5020E")]
        [TestCase(HashType.SHA1, "key", "6FD75D8D3D3A7FB244F04178AA50C8AF2180BA72")]
        [TestCase(HashType.SHA256, "key", "F7AAE2D999881387B8362976AD878D041527F78F7EFF7D1EAFA1A6212A2A4061")]
        [TestCase(HashType.SHA384, "key", "B78E547A75A256B7902F05378D452AB6C8192D48232E312B466E40E5ED9BE1A5B77053251C5D0177EFF1DDC2A6DE9B1E")]
        [TestCase(HashType.SHA512, "key", "A300C834A06AA8935B27991C2F3D044009AC1952E0B51845DD8AE2178F778C82F012C3A343266C41A493A8D16966C25A4F88E2A8FBEAE6AD8D5F0AA6FE29665A")]
        public void CreateAndCreateFromString(HashType hashType, string secretKey, string hash)
        {
            const string data = "Hello";
            var digest1 = Digest.Create(hashType, data, secretKey);
            Assert.AreEqual(hash, digest1.Hash);
            Assert.AreEqual(data, digest1.Data);
            Assert.AreEqual(hashType, digest1.HashType);

            // Check its reversable
            var digest1String = digest1.ToString();
            var digest2 = Digest.CreateFromString(digest1String, secretKey);
            Assert.AreEqual(digest1.Data, digest2.Data);
            Assert.AreEqual(digest1.Hash, digest2.Hash);
            Assert.AreEqual(hashType, digest2.HashType);
        }
    }
}