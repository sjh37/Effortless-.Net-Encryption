// <copyright file="BytesTest.cs" company="Simon Hughes">Copyright © Simon Hughes 2012</copyright>

using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Pex.Framework;
using Microsoft.Pex.Framework.Generated;
using Microsoft.Pex.Framework.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Effortless.Net.Encryption
{
    [TestClass]
    [PexClass(typeof(Bytes))]
    [PexAllowedExceptionFromTypeUnderTest(typeof(ArgumentException), AcceptExceptionSubtypes = true)]
    [PexAllowedExceptionFromTypeUnderTest(typeof(InvalidOperationException))]
    public partial class BytesTest
    {
        [PexMethod, PexAllowedException(typeof(CryptographicException))]
        public void Encrypt02(string fileIn, string fileOut, byte[] key, byte[] iv)
        {
            Bytes.Encrypt(fileIn, fileOut, key, iv);
            // TODO: add assertions to method BytesTest.Encrypt02(String, String, Bytes[], Bytes[])
        }

        [PexMethod, PexAllowedException(typeof(CryptographicException))]
        public void Encrypt02(Stream fileIn, string fileOut, byte[] key, byte[] iv)
        {
            Bytes.Encrypt(fileIn, fileOut, key, iv);
            // TODO: add assertions to method BytesTest.Encrypt02(Stream, String, Bytes[], Bytes[])
        }

        [PexMethod, PexAllowedException(typeof(ArgumentException))]
        public void Encrypt01(Stream fsIn, string fileOut, RijndaelManaged alg)
        {
            Bytes.Encrypt(fsIn, fileOut, alg);
            // TODO: add assertions to method BytesTest.Encrypt01(Stream, String, RijndaelManaged)
        }

        [PexMethod, PexAllowedException(typeof(ArgumentException))]
        public void Decrypt04(string fileIn, Stream fsOut, string key, string iv)
        {
            Bytes.Decrypt(fileIn, fsOut, key, iv);
            // TODO: add assertions to method BytesTest.Decrypt04(String, Stream, String, String)
        }

        [PexMethod, PexAllowedException(typeof(CryptographicException))]
        public byte[] Encrypt(byte[] clearData, byte[] key, byte[] iv)
        {
            byte[] result = Bytes.Encrypt(clearData, key, iv);
            return result;
            // TODO: add assertions to method BytesTest.Encrypt(Bytes[], Bytes[], Bytes[])
        }

        [PexMethod, PexAllowedException(typeof(ArgumentException))]
        public void Encrypt01(string fileIn, string fileOut, out string key, out string iv)
        {
            Bytes.Encrypt(fileIn, fileOut, out key, out iv);
            // TODO: add assertions to method BytesTest.Encrypt01(String, String, String&, String&)
        }

        [PexMethod, PexAllowedException(typeof(CryptographicException))]
        public byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv)
        {
            byte[] result = Bytes.Decrypt(cipherData, key, iv);
            return result;
            // TODO: add assertions to method BytesTest.Decrypt(Bytes[], Bytes[], Bytes[])
        }

        [PexMethod, PexAllowedException(typeof(ArgumentException))]
        public void Decrypt01(string fileIn, string fileOut, byte[] key, byte[] iv)
        {
            Bytes.Decrypt(fileIn, fileOut, key, iv);
            // TODO: add assertions to method BytesTest.Decrypt01(String, String, Bytes[], Bytes[])
        }

        [PexMethod, PexAllowedException(typeof(FormatException))]
        public void Decrypt01(string fileIn, string fileOut, string key, string iv)
        {
            Bytes.Decrypt(fileIn, fileOut, key, iv);
            // TODO: add assertions to method BytesTest.Decrypt01(String, String, String, String)
        }

        [PexMethod, PexAllowedException(typeof(ArgumentException))]
        public void Encrypt(Stream fileIn, string fileOut, out string key, out string iv)
        {
            Bytes.Encrypt(fileIn, fileOut, out key, out iv);
            // TODO: add assertions to method BytesTest.Encrypt(Stream, String, String&, String&)
        }

        [PexMethod]
        public byte[] GenerateKey01(string password, string salt, Bytes.KeySize keySize)
        {
            byte[] result = Bytes.GenerateKey(password, salt, keySize);
            return result;
            // TODO: add assertions to method BytesTest.GenerateKey01(String, String, Int32)
        }

        [PexMethod]
        public byte[] GenerateKey()
        {
            byte[] result = Bytes.GenerateKey();
            return result;
            // TODO: add assertions to method BytesTest.GenerateKey()
        }

        [PexMethod]
        public byte[] GenerateIV()
        {
            byte[] result = Bytes.GenerateIV();
            return result;
            // TODO: add assertions to method BytesTest.GenerateIV()
        }

        [PexMethod]
        public void Decrypt(FileStream fsIn, Stream fsOut, RijndaelManaged alg)
        {
            Bytes.Decrypt(fsIn, fsOut, alg);
            // TODO: add assertions to method BytesTest.Decrypt(FileStream, Stream, RijndaelManaged)
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException377()
        {
            byte[] bs;
            bs = GenerateKey01("\ud801", "\ud801\ud880\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException324()
        {
            byte[] bs;
            bs = GenerateKey01("\ud801", "\ud801\ud880", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException132()
        {
            byte[] bs;
            bs = GenerateKey01("\ud801", "\ud801", Bytes.KeySize.Size256);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException570()
        {
            byte[] bs;
            bs = GenerateKey01("\ud801\u0c00", "\ud801\u0c00\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        public void GenerateKey01711()
        {
            byte[] bs;
            bs = GenerateKey01("\0", "\0\0\0\0\0\0\u0080\u0080\0\0\0\0\0\0\0", Bytes.KeySize.Size128);
            Assert.IsNotNull(bs);
            Assert.AreEqual(16, (bs.Length));
            Assert.AreEqual((byte)110, bs[0]);
            Assert.AreEqual((byte)168, bs[1]);
            Assert.AreEqual((byte)229, bs[2]);
            Assert.AreEqual((byte)178, bs[3]);
            Assert.AreEqual((byte)227, bs[4]);
            Assert.AreEqual((byte)208, bs[5]);
            Assert.AreEqual((byte)154, bs[6]);
            Assert.AreEqual((byte)47, bs[7]);
            Assert.AreEqual((byte)80, bs[8]);
            Assert.AreEqual((byte)152, bs[9]);
            Assert.AreEqual((byte)132, bs[10]);
            Assert.AreEqual((byte)21, bs[11]);
            Assert.AreEqual((byte)26, bs[12]);
            Assert.AreEqual((byte)250, bs[13]);
            Assert.AreEqual((byte)95, bs[14]);
            Assert.AreEqual((byte)169, bs[15]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException163()
        {
            byte[] bs;
            bs = GenerateKey01("\udc00", "\udc00", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void GenerateKey01ThrowsArgumentNullException359()
        {
            byte[] bs;
            bs = GenerateKey01("\0", null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void GenerateKey01ThrowsArgumentNullException357()
        {
            byte[] bs;
            bs = GenerateKey01(null, null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException761()
        {
            byte[] bs;
            bs = GenerateKey01("\0", "\0", Bytes.KeySize.Size192);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException621()
        {
            byte[] bs;
            bs = GenerateKey01("\u0080", "\u0080\u0080\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException158()
        {
            byte[] bs;
            bs = GenerateKey01("\0", "\0", 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException155()
        {
            byte[] bs;
            bs = GenerateKey01("\0", "\0\0\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException114()
        {
            byte[] bs;
            bs = GenerateKey01("\0", "\0", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateKey01ThrowsArgumentException53()
        {
            byte[] bs;
            bs = GenerateKey01("\u0080", "\u0080", Bytes.KeySize.Size128);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt02ThrowsCryptographicException858()
        {
            var bs = new byte[1];
            var bs1 = new byte[1];
            Encrypt02("\0", "\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException558()
        {
            var bs = new byte[1];
            Encrypt02("\0", "\0", bs, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException421()
        {
            Encrypt02("\0", "\0", null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException370()
        {
            Encrypt02((string)null, null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException162()
        {
            Encrypt02("\0", null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException30()
        {
            var bs = new byte[0];
            Encrypt02("\0", "\0", bs, null);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt02ThrowsCryptographicException848()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[1];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[1];
                var bs2 = new byte[1];
                Encrypt02(memoryStream, "\0", bs1, bs2);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException233()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[1];
                Encrypt02(memoryStream, "\0", bs1, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException793()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[0];
                Encrypt02(memoryStream, "\0", bs1, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException326()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt02(memoryStream, "\0", null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException832()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt02(memoryStream, null, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException676()
        {
            Encrypt02((Stream)null, null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException782()
        {
            var s = (string)null;
            var s1 = (string)null;
            Encrypt01("\0", null, out s, out s1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException347()
        {
            var s = (string)null;
            var s1 = (string)null;
            Encrypt01(null, "", out s, out s1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException338()
        {
            var s = (string)null;
            var s1 = (string)null;
            Encrypt01("\0", "\0", out s, out s1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException174()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                RijndaelManaged rijndaelManaged;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                rijndaelManaged = new RijndaelManaged();
                disposables.Add(rijndaelManaged);
                Encrypt01(memoryStream, "\0", rijndaelManaged);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException470()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt01(memoryStream, "\0", null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException211()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt01(memoryStream, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException257()
        {
            Encrypt01(null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptThrowsArgumentException288()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var s = (string)null;
                var s1 = (string)null;
                Encrypt(memoryStream, "\0", out s, out s1);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException6()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var s = (string)null;
                var s1 = (string)null;
                Encrypt(memoryStream, null, out s, out s1);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException654()
        {
            var s = (string)null;
            var s1 = (string)null;
            Encrypt(null, "", out s, out s1);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void EncryptThrowsCryptographicException630()
        {
            byte[] bs;
            var bs1 = new byte[1];
            var bs2 = new byte[1];
            var bs3 = new byte[1];
            bs = Encrypt(bs1, bs2, bs3);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException863()
        {
            byte[] bs;
            var bs1 = new byte[1];
            var bs2 = new byte[1];
            bs = Encrypt(bs1, bs2, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException472()
        {
            byte[] bs;
            bs = Encrypt(null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException331()
        {
            byte[] bs;
            var bs1 = new byte[1];
            bs = Encrypt(bs1, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException34()
        {
            byte[] bs;
            var bs1 = new byte[0];
            bs = Encrypt(bs1, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt04ThrowsArgumentException964()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("\0", memoryStream, "\0", "\0");
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException358()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("\0", memoryStream, "\0", null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException530()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("", memoryStream, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException112()
        {
            Decrypt04(null, null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException63()
        {
            Decrypt04("", null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void Decrypt01ThrowsFormatException421()
        {
            Decrypt01("\0", "\0", "\0", "\0");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException923()
        {
            Decrypt01("\0", null, null, (string)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException861()
        {
            Decrypt01("\0", "\0", null, (string)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException572()
        {
            Decrypt01(null, null, null, (string)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException45()
        {
            Decrypt01("\0", "\0", "\0", null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException924()
        {
            Decrypt01(null, null, null, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException878()
        {
            var bs = new byte[1];
            Decrypt01("\0", "\0", bs, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException780()
        {
            Decrypt01("\0", null, null, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException733()
        {
            Decrypt01("\0", "\0", null, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt01ThrowsArgumentNullException95()
        {
            var bs = new byte[0];
            Decrypt01("\0", "\0", bs, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt01ThrowsArgumentException11()
        {
            var bs = new byte[1];
            var bs1 = new byte[1];
            Decrypt01("\0", "\0", bs, bs1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException928()
        {
            Decrypt(null, null, (RijndaelManaged)null);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void DecryptThrowsCryptographicException50()
        {
            byte[] bs;
            var bs1 = new byte[1];
            var bs2 = new byte[1];
            var bs3 = new byte[1];
            bs = Decrypt(bs1, bs2, bs3);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException551()
        {
            byte[] bs;
            var bs1 = new byte[0];
            bs = Decrypt(bs1, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException499()
        {
            byte[] bs;
            var bs1 = new byte[0];
            var bs2 = new byte[1];
            bs = Decrypt(bs1, bs2, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException410()
        {
            byte[] bs;
            bs = Decrypt(null, null, (byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptThrowsArgumentNullException324()
        {
            byte[] bs;
            var bs1 = new byte[0];
            var bs2 = new byte[0];
            bs = Decrypt(bs1, bs2, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecryptThrowsArgumentException974()
        {
            byte[] bs;
            var bs1 = new byte[0];
            var bs2 = new byte[1];
            var bs3 = new byte[1];
            bs = Decrypt(bs1, bs2, bs3);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt04ThrowsArgumentException435()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("\0", memoryStream, "\0", "\0");
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException635()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("\0", memoryStream, "\0", null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException912()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("", memoryStream, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptThrowsArgumentException287()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var s = (string)null;
                var s1 = (string)null;
                Encrypt(memoryStream, "\0", out s, out s1);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException898()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var s = (string)null;
                var s1 = (string)null;
                Encrypt(memoryStream, null, out s, out s1);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException809()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt01(memoryStream, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException685()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt01(memoryStream, "\0", null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException645()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                RijndaelManaged rijndaelManaged;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                rijndaelManaged = new RijndaelManaged();
                disposables.Add(rijndaelManaged);
                Encrypt01(memoryStream, "\0", rijndaelManaged);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException885()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt02(memoryStream, null, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException606()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt02(memoryStream, "\0", null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException733()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[0];
                Encrypt02(memoryStream, "\0", bs1, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException280()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[1];
                Encrypt02(memoryStream, "\0", bs1, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt02ThrowsCryptographicException220()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[1];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[1];
                var bs2 = new byte[1];
                Encrypt02(memoryStream, "\0", bs1, bs2);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptThrowsArgumentException757()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var s = (string)null;
                var s1 = (string)null;
                Encrypt(memoryStream, "\0", out s, out s1);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptThrowsArgumentNullException933()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var s = (string)null;
                var s1 = (string)null;
                Encrypt(memoryStream, null, out s, out s1);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt04ThrowsArgumentException399()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("\0", memoryStream, "\0", "\0");
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException179()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("\0", memoryStream, "\0", null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Decrypt04ThrowsArgumentNullException632()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Decrypt04("", memoryStream, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Encrypt01ThrowsArgumentException502()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                RijndaelManaged rijndaelManaged;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                rijndaelManaged = new RijndaelManaged();
                disposables.Add(rijndaelManaged);
                Encrypt01(memoryStream, "\0", rijndaelManaged);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException74()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt01(memoryStream, "\0", null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt01ThrowsArgumentNullException70()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt01(memoryStream, null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypt02ThrowsCryptographicException393()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[1];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[1];
                var bs2 = new byte[1];
                Encrypt02(memoryStream, "\0", bs1, bs2);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException211()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[1];
                Encrypt02(memoryStream, "\0", bs1, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException828()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                var bs1 = new byte[0];
                Encrypt02(memoryStream, "\0", bs1, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException377()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt02(memoryStream, "\0", null, null);
                disposables.Dispose();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Encrypt02ThrowsArgumentNullException476()
        {
            using(PexDisposableContext disposables = PexDisposableContext.Create())
            {
                MemoryStream memoryStream;
                var bs = new byte[0];
                memoryStream = new MemoryStream(bs, false);
                disposables.Add(memoryStream);
                Encrypt02(memoryStream, null, null, null);
                disposables.Dispose();
            }
        }
    }
}