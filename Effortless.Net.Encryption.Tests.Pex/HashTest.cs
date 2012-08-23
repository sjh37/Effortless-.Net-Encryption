// <copyright file="HashTest.cs" company="Simon Hughes">Copyright © Simon Hughes 2012</copyright>

using System;
using Microsoft.Pex.Framework;
using Microsoft.Pex.Framework.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Effortless.Net.Encryption;
using Microsoft.Pex.Framework.Generated;

namespace Effortless.Net.Encryption
{
    [TestClass]
    [PexClass(typeof(Hash))]
    [PexAllowedExceptionFromTypeUnderTest(typeof(ArgumentException), AcceptExceptionSubtypes = true)]
    [PexAllowedExceptionFromTypeUnderTest(typeof(InvalidOperationException))]
    public partial class HashTest
    {
        [PexMethod]
        public string Create(HashType hashType, string data, string sharedKey, bool showBytes)
        {
            string result = Hash.Create(hashType, data, sharedKey, showBytes);
            return result;
            // TODO: add assertions to method HashTest.Create(HashType, String, String, Boolean)
        }

        [TestMethod]
        public void Create701()
        {
            string s;
            s = this.Create(HashType.SHA384, "\0", "", false);
            Assert.AreEqual<string>("vsAhtPNo4waRNOASwrQwcIPTqb3SBuJOXw2G4T1mNmVZM+wrQTRllmgXqcIIoRcX", s);
        }

        [TestMethod]
        public void Create823()
        {
            string s;
            s = this.Create(HashType.SHA256, "\0", "", false);
            Assert.AreEqual<string>("bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=", s);
        }

        [TestMethod]
        public void Create997()
        {
            string s;
            s = this.Create(HashType.SHA1, "\udc00", "", false);
            Assert.AreEqual<string>("m9t3J2wYUuH7BnggRygS/PYIQCQ=", s);
        }

        [TestMethod]
        public void Create854()
        {
            string s;
            s = this.Create(HashType.SHA512, "\udc00", "", false);
            Assert.AreEqual<string>("fVm3QJ0bu1qVSI4a7LMX+6eUq1qywsjo+KoA78nJSgPMroiERy1T5A18RnJ7HQfHG/XHQeQhWl1aB24jrcLYfg==", s);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void CreateThrowsArgumentOutOfRangeException123()
        {
            string s;
            s = this.Create((HashType)6, (string)null, (string)null, false);
        }

        [TestMethod]
        public void Create98()
        {
            string s;
            s = this.Create(HashType.MD5, "\udc00", "", true);
            Assert.AreEqual<string>("9B759040321A408A5C7768B4511287A6", s);
        }

        [TestMethod]
        public void Create147()
        {
            string s;
            s = this.Create(HashType.MD5, "\udc00", "", false);
            Assert.AreEqual<string>("m3WQQDIaQIpcd2i0URKHpg==", s);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateThrowsArgumentNullException757()
        {
            string s;
            s = this.Create(HashType.SHA512, (string)null, (string)null, false);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateThrowsArgumentNullException735()
        {
            string s;
            s = this.Create(HashType.SHA384, (string)null, (string)null, false);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateThrowsArgumentNullException164()
        {
            string s;
            s = this.Create(HashType.SHA256, (string)null, (string)null, false);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateThrowsArgumentNullException940()
        {
            string s;
            s = this.Create(HashType.MD5, "\0", (string)null, false);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateThrowsArgumentNullException477()
        {
            string s;
            s = this.Create(HashType.SHA1, (string)null, (string)null, false);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateThrowsArgumentNullException17()
        {
            string s;
            s = this.Create(HashType.MD5, (string)null, (string)null, false);
        }
    }
}