using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using OneIdentity.SafeguardDotNet;
using Xunit;

namespace SafeguardDotNet.Test
{
    public class CertificateContextTests
    {
        private const string CertThumb = "ec1c1c5862471c27925b9c7180eb4facf8398c58";
        private const string CertFilePath = "test.full.pfx";
        private const string CertPassword = "test123";

        [Fact]
        public void CanCloneCertificate()
        {
            var ss = new SecureString();
            foreach (var ch in CertPassword) { ss.AppendChar(ch); }
            var pfxFile = GetDataFilePath(CertFilePath);

            X509Certificate2 x509Cert;
            using (var ctx = new CertificateContext(new FileCertificateResolver(pfxFile, ss)))
            {
                using (var ctx2 = ctx.Clone())
                {
                    var test = ctx2.Certificate;
                    Assert.Equal(CertThumb, test.Thumbprint, ignoreCase: true);
                    x509Cert = new X509Certificate2(test);
                }
                Assert.Equal(CertThumb, ctx.Certificate.Thumbprint, ignoreCase:true);
            }
            Assert.NotNull(x509Cert);
            x509Cert.Dispose();
        }

        public static string GetDataFilePath(string relativePath)
        {
            string[] importPaths =
            {
                @"data", @"..\data", @"..\..\data", @"..\..\..\data", @"..\..\..\..\data"
            };
            var importPath = importPaths.FirstOrDefault(Directory.Exists);
            if (string.IsNullOrEmpty(importPath)) throw new Exception("data path not found!");
            return Path.Combine(importPath, relativePath);
        }
    }
}
