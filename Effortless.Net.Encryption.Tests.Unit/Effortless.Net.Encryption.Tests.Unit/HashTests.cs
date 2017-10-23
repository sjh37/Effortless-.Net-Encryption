using NUnit.Framework;

namespace Effortless.Net.Encryption.Tests.Unit
{
    [TestFixture]
    public class HashTests
    {
        [Test]
        [TestCase(true, HashType.MD5, "6E721FFDDD9974CC99A10A3D04385B33")]
        [TestCase(true, HashType.SHA1, "E483166C1BCA40E5A1289D6416C6DE1A271F2ACE")]
        [TestCase(true, HashType.SHA256, "C63338687D9BC4E95350C465D392DB3518C777AE3A04284005B358350767A710")]
        [TestCase(true, HashType.SHA384, "584BE855D030A6E25C07909751D3762429C3C811935CB57A34AD686F82FDAFAF1F72594BBE38CA0C95EDD2DD81E9035A")]
        [TestCase(true, HashType.SHA512, "ABCB5D5F7DE874D6AB172E69106FEE23B9957CF074DDE23CD0A9A29D8E56E4EC0D73C42F63C633FFB68C8E8955F2C220EA97FF65C12402DFC9B2911422062842")]
        [TestCase(false, HashType.MD5, "bnIf/d2ZdMyZoQo9BDhbMw==")]
        [TestCase(false, HashType.SHA1, "5IMWbBvKQOWhKJ1kFsbeGicfKs4=")]
        [TestCase(false, HashType.SHA256, "xjM4aH2bxOlTUMRl05LbNRjHd646BChABbNYNQdnpxA=")]
        [TestCase(false, HashType.SHA384, "WEvoVdAwpuJcB5CXUdN2JCnDyBGTXLV6NK1ob4L9r68fcllLvjjKDJXt0t2B6QNa")]
        [TestCase(false, HashType.SHA512, "q8tdX33odNarFy5pEG/uI7mVfPB03eI80KminY5W5OwNc8QvY8Yz/7aMjolV8sIg6pf/ZcEkAt/JspEUIgYoQg==")]
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
        [TestCase(true, HashType.MD5, "8B1A9953C4611296A827ABF8C47804D7")]
        [TestCase(true, HashType.SHA1, "F7FF9E8B7BB2E09B70935A5D785E0CC5D9D0ABF0")]
        [TestCase(true, HashType.SHA256, "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969")]
        [TestCase(true, HashType.SHA384, "3519FE5AD2C596EFE3E276A6F351B8FC0B03DB861782490D45F7598EBD0AB5FD5520ED102F38C4A5EC834E98668035FC")]
        [TestCase(true, HashType.SHA512, "3615F80C9D293ED7402687F94B22D58E529B8CC7916F8FAC7FDDF7FBD5AF4CF777D3D795A7A00A16BF7E7F3FB9561EE9BAAE480DA9FE7A18769E71886B03F315")]
        [TestCase(false, HashType.MD5, "ixqZU8RhEpaoJ6v4xHgE1w==")]
        [TestCase(false, HashType.SHA1, "9/+ei3uy4Jtwk1pdeF4MxdnQq/A=")]
        [TestCase(false, HashType.SHA256, "GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=")]
        [TestCase(false, HashType.SHA384, "NRn+WtLFlu/j4nam81G4/AsD24YXgkkNRfdZjr0Ktf1VIO0QLzjEpeyDTphmgDX8")]
        [TestCase(false, HashType.SHA512, "NhX4DJ0pPtdAJof5SyLVjlKbjMeRb4+sf933+9WvTPd309eVp6AKFr9+fz+5Vh7puq5IDan+ehh2nnGIawPzFQ==")]
        public void CreateWithNoKey(bool showBytes, HashType hashType, string result)
        {
            const string data = "Hello";
            var hash = Hash.Create(hashType, data, string.Empty, showBytes);
            Assert.AreEqual(result, hash);
            Assert.IsTrue(Hash.Verify(hashType, data, string.Empty, showBytes, hash));
            Assert.IsFalse(Hash.Verify(hashType, data, "unknownKey", showBytes, hash));
        }
    }
}