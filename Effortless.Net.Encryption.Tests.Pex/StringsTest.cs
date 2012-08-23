// <copyright file="StringsTest.cs" company="Simon Hughes">Copyright © Simon Hughes 2012</copyright>

using System;
using Microsoft.Pex.Framework;
using Microsoft.Pex.Framework.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Effortless.Net.Encryption;
using System.Security.Cryptography;
using Microsoft.Pex.Framework.Generated;

namespace Effortless.Net.Encryption
{
    [TestClass]
    [PexClass(typeof(Strings))]
    [PexAllowedExceptionFromTypeUnderTest(typeof(ArgumentException), AcceptExceptionSubtypes = true)]
    [PexAllowedExceptionFromTypeUnderTest(typeof(InvalidOperationException))]
    public partial class StringsTest
    {
        [PexMethod, PexAllowedException(typeof(ArgumentException)), PexAllowedException(typeof(CryptographicException))]
        public string Encrypt01(string clearString, string password, string salt, string iv, Bytes.KeySize keySize)
        {
            string result = Strings.Encrypt(clearString, password, salt, iv, keySize);
            return result;
            // TODO: add assertions to method StringsTest.Encrypt01(String, String, String, String, Int32)
        }

        [PexMethod, PexAllowedException(typeof(FormatException))]
        public string Decrypt(string cipherString, byte[] key, byte[] iv)
        {
            string result = Strings.Decrypt(cipherString, key, iv);
            return result;
            // TODO: add assertions to method StringsTest.Decrypt(String, Bytes[], Bytes[])
        }

        [PexMethod, PexAllowedException(typeof(ArgumentException)), PexAllowedException(typeof(FormatException))]
        public string Decrypt(string cipherString, string password, string salt, string iv, Bytes.KeySize keySize)
        {
            string result = Strings.Decrypt(cipherString, password, salt, iv, keySize);
            return result;
            // TODO: add assertions to method StringsTest.Decrypt(String, String, String, String, Int32)
        }

        [PexMethod, PexAllowedException(typeof(CryptographicException))]
        public string Encrypt(string clearString, byte[] key, byte[] iv)
        {
            string result = Strings.Encrypt(clearString, key, iv);
            return result;
            // TODO: add assertions to method StringsTest.Encrypt(String, Bytes[], Bytes[])
        }

        [PexMethod]
        public string CreateSaltFull(int size)
        {
            string result = Strings.CreateSaltFull(size);
            return result;
            // TODO: add assertions to method StringsTest.CreateSaltFull(Int32)
        }

        [PexMethod]
        public string CreateSalt(int size)
        {
            string result = Strings.CreateSalt(size);
            return result;
            // TODO: add assertions to method StringsTest.CreateSalt(Int32)
        }

        [PexMethod]
        public string CreatePassword(int size, bool allowPunctuation)
        {
            string result = Strings.CreatePassword(size, allowPunctuation);
            return result;
            // TODO: add assertions to method StringsTest.CreatePassword(Int32, Boolean)
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException155()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0\0\0\0\0\0\0\0\u0080\u0080\u0080\u0080\u0080\u0080", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException631()
        {
            string s;
            s = this.Encrypt01("\0\0\0\0", "\0", "\0\0\0\0\0\0\u0080\0\uc000\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException762()
        {
            string s;
            s = this.Encrypt01("\ud800\udc00\0\0\ud800\0\0\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException561()
        {
            string s;
            s = this.Encrypt01("\0\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0\u0080\0\0\0\ua000\u0080\u0080\u0080\u0080\ud880\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException754()
        {
            string s;
            s = this.Encrypt01("\udc00", "\udc00", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\udc00\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException54()
        {
            string s;
            s = this.Encrypt01("\ud800", "\ud800", new string('\0', 15), "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException2()
        {
            string s;
            s = this.Encrypt01("\ud800\udc00\0\0\udc00\0\0\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException99()
        {
            string s;
            s = this.Encrypt01("\ud800\udc00\0\0\u8000\0\0\0\0\0\0\0\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException548()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0\u0080", "\0\u0080", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException839()
        {
            string s;
            s = this.Encrypt01("\ud801", "\ud801", "\ud801\0\0", "\ud801", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException5()
        {
            string s;
            s = this.Encrypt01("\udc00\0\0\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [PexDescription("the test state was: duplicate path")]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException545()
        {
            string s;
            s = this.Encrypt01("\0", "\ud9c0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\ud9c0\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException231()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\ud9c0\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException644()
        {
            string s;
            s = this.Encrypt01("\ud800\ue000", "\ud800", "\0\0\0\0\0\0\0\u0100\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException342()
        {
            string s;
            s = this.Encrypt01("\ud800\udc00\0\0\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException646()
        {
            string s;
            s = this.Encrypt01("\0\u8000", "\0\u8000", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException317()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException979()
        {
            string s;
            s = this.Encrypt01("\ud800", "\ud800", "\0\0\0\0\0\0\0\u0080\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt01ThrowsCryptographicException961()
        {
            string s;
            s = this.Encrypt01("\udc00", "\udc00", "\0\0\0\0\0\0\0\u0100\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException129()
        {
            string s;
            s = this.Encrypt01("\ud801", "\ud801", "\ud801", "\ud801", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException121()
        {
            string s;
            s = this.Encrypt01("\ud801", "\ud801", "\ud801", "\ud801", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException437()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0", "\0", Bytes.KeySize.Size192);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException194()
        {
            string s;
            s = this.Encrypt01("\udc00", "\udc00", "\udc00", "\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException641()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException93()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0", "\0", 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException765()
        {
            string s;
            s = this.Encrypt01("\0", "\0", "\0", (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException317()
        {
            string s;
            s = this.Encrypt01("\0", "\0", (string)null, (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException797()
        {
            string s;
            s = this.Encrypt01("\0", (string)null, (string)null, (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException713()
        {
            string s;
            s = this.Encrypt01((string)null, (string)null, (string)null, (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException183()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\udc00", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException439()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\ue000\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException967()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\0\0\0\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException290()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException766()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\0\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException201()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\udc00", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException859()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException13()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt((string)null, bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException972()
        {
            string s;
            byte[] bs = new byte[1];
            s = this.Encrypt((string)null, bs, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException336()
        {
            string s;
            byte[] bs = new byte[0];
            s = this.Encrypt((string)null, bs, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException466()
        {
            string s;
            s = this.Encrypt((string)null, (byte[])null, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException261()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\ud800\udc00\0\ua000\0\0\0\0\0\0\0",
                             "\0\0\0\0\0\u0800\0\0\uc000\0\0\0\udc00\udc00\udc00\udc00\udc00\udc00\u0800\0\0\0\0\0\0\0\0\0\0\0\0\0", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException809()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\ud800\udc00\0\uc000\0\0\0\0\0\0\0", "\0\0\0\0\0\u0800\0\0\ud801\ud900\ud880\ud880\ud880\ud880\ud880", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException691()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\0\0\u0080\0\u0080\u0800\0\0\0\0\0\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException336()
        {
            string s;
            s = this.Decrypt("\0", "\0\u0080", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\0\u0080\0\0\u0100\0\0\0\0\0\0\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException1()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\0\0\u0100\u0400\u0100\u0400\0\0\u0080\0\0\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException69()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\ud800\udc00\0\u7800\0\0\0\0\0\0\0", "\0\0\0\0\uc000\0\ud804\ud900\ud880\ud900\ud880\ud880\ud880\ud880\ud880", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException318()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801", "\ud801\ud800\udc00\0\0\0\0\0\0\0\0\0\0\0\0", "\ud801", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException701()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\u0080\0\0\0\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException909()
        {
            string s;
            s = this.Decrypt("\0\0", "\0", "\0\0\0\0\0\0\u0400\u0100\0\u0100\0\0\0\0\0", "\0\0\u0080\u0080\u0080\u0080\0\0\u0080\u0800\0\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException243()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\0\0\0\0\ua000\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException31()
        {
            string s;
            s = this.Decrypt("\0\u0080\u0080\u0080", "\0\u0080", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0",
                             "\0\u0080\u0080\u0080\u0200\u0080\u0400\u0080\u0400\u0080\0\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException269()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\ud801\0\0\0\0\0\0\0\0\0\0", "\0", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException291()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\0\0\0\0\u0800\0\0\0\0\0\0", "\0\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException408()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801\ud880", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\ud801\ud880\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException21()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801\u0080", "\0\0\0\0\0\0\u0080\u0100\0\u0100\0\0\0\0\0", "\ud801\u0080", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException257()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\0\u0080", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException252()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801", "\0\0\0\0\0\0\u0100\u0080\0\u0080\0\0\0\0\0", "\ud801\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException810()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0", "\0", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException927()
        {
            string s;
            s = this.Decrypt("\u0080", "\u0080", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\u0080", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException300()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\ud801", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException367()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801", "\ud801\0\0", "\ud801", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException391()
        {
            string s;
            s = this.Decrypt("\ud801", "\ud801", "\ud801", "\ud801", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException218()
        {
            string s;
            s = this.Decrypt("\0", "\0\0", "\0\0\0\0\0\0\u0080\u0080\0\u0080\0\0\0\0\0", "\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException267()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0", "\0", Bytes.KeySize.Size192);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException426()
        {
            string s;
            s = this.Decrypt("\udc00", "\udc00", "\udc00", "\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException74()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException421()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0", "\0", 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException436()
        {
            string s;
            s = this.Decrypt("\0", "\0", "\0", (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException515()
        {
            string s;
            s = this.Decrypt("\0", "\0", (string)null, (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException868()
        {
            string s;
            s = this.Decrypt("\0", (string)null, (string)null, (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException130()
        {
            string s;
            s = this.Decrypt((string)null, (string)null, (string)null, (string)null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DecryptThrowsFormatException349()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Decrypt("\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException273()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Decrypt((string)null, bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException318()
        {
            string s;
            byte[] bs = new byte[1];
            s = this.Decrypt((string)null, bs, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException564()
        {
            string s;
            byte[] bs = new byte[0];
            s = this.Decrypt((string)null, bs, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException753()
        {
            string s;
            s = this.Decrypt((string)null, (byte[])null, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateSaltFullThrowsArgumentException990()
        {
            string s;
            s = this.CreateSaltFull(0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateSaltThrowsArgumentException12()
        {
            string s;
            s = this.CreateSalt(0);
        }


        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreatePasswordThrowsArgumentException540()
        {
            string s;
            s = this.CreatePassword(0, false);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException170()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\0\0\0\0\ue000\ud800\0\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException12()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\0\ud800\0\0\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException82()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\0\0\0\0\0\u8000\0\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException8()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\0\0\0\u8000\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException99()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\ud800\0\ud800", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException364()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\udc00\ud800\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException160()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\udc00\udc00\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException619()
        {
            string s;
            byte[] bs = new byte[1];
            byte[] bs1 = new byte[1];
            s = this.Encrypt("\0\0\0\0\0", bs, bs1);
        }
    }
}