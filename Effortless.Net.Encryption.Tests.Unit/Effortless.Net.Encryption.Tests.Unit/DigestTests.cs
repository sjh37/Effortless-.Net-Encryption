using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    public class DigestTests
    {
        [Test]
        [TestCase(HashType.MD5, "", "8B1A9953C4611296A827ABF8C47804D7")]
        [TestCase(HashType.SHA1, "", "F7FF9E8B7BB2E09B70935A5D785E0CC5D9D0ABF0")]
        [TestCase(HashType.SHA256, "", "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969")]
        [TestCase(HashType.SHA384, "", "3519FE5AD2C596EFE3E276A6F351B8FC0B03DB861782490D45F7598EBD0AB5FD5520ED102F38C4A5EC834E98668035FC")]
        [TestCase(HashType.SHA512, "", "3615F80C9D293ED7402687F94B22D58E529B8CC7916F8FAC7FDDF7FBD5AF4CF777D3D795A7A00A16BF7E7F3FB9561EE9BAAE480DA9FE7A18769E71886B03F315")]
        [TestCase(HashType.MD5, "key", "6E721FFDDD9974CC99A10A3D04385B33")]
        [TestCase(HashType.SHA1, "key", "E483166C1BCA40E5A1289D6416C6DE1A271F2ACE")]
        [TestCase(HashType.SHA256, "key", "C63338687D9BC4E95350C465D392DB3518C777AE3A04284005B358350767A710")]
        [TestCase(HashType.SHA384, "key", "584BE855D030A6E25C07909751D3762429C3C811935CB57A34AD686F82FDAFAF1F72594BBE38CA0C95EDD2DD81E9035A")]
        [TestCase(HashType.SHA512, "key", "ABCB5D5F7DE874D6AB172E69106FEE23B9957CF074DDE23CD0A9A29D8E56E4EC0D73C42F63C633FFB68C8E8955F2C220EA97FF65C12402DFC9B2911422062842")]
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