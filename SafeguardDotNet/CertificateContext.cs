using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Serilog;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// Resolves certificates
    /// </summary>
    internal interface ICertificateResolver : IDisposable
    {
        /// <summary>
        /// Resolves a certificate. The caller owns the returned certificate and must
        /// dispose it.
        /// </summary>
        X509Certificate2 Resolve();

        /// <summary>
        /// Returns a clone of the certificate resolver. The caller owns the clone and
        /// must dispose it.
        /// </summary>
        ICertificateResolver Clone();
    }

    internal class CertificateContext : IDisposable
    {
        public CertificateContext(ICertificateResolver resolver)
        {
            CertificateResolver = resolver;
            Certificate = resolver.Resolve();
        }

        private ICertificateResolver CertificateResolver { get; }
        public X509Certificate2 Certificate { get; }

        public CertificateContext Clone()
        {
            return new CertificateContext(CertificateResolver.Clone());
        }

        public override string ToString()
        {
            return CertificateResolver.ToString();
        }

        public void Dispose()
        {
            CertificateResolver?.Dispose();
            Certificate?.Dispose();
        }
    }

    internal class FileCertificateResolver : ICertificateResolver
    {
        /// <summary>
        /// Resolve the certificate from a pfx file
        /// </summary>
        /// <param name="filepath">Path to the pfx file</param>
        /// <param name="password">Password to decrypt the file</param>
        public FileCertificateResolver(string filepath, SecureString password)
        {
            FilePath = filepath;
            Password = password;
        }

        private string FilePath { get; set; }
        private SecureString Password { get; set; } 


        public X509Certificate2 Resolve()
        {
            return CertificateUtilities.GetClientCertificateFromFile(FilePath, Password);
        }

        public ICertificateResolver Clone()
        {
            return new FileCertificateResolver(FilePath, Password);
        }

        public void Dispose()
        {
            Password?.Dispose();
        }

        public override string ToString()
        {
            return $"file={FilePath}";
        }
    }


    internal class StoreCertificateResolver : ICertificateResolver
    {
        /// <summary>
        /// Resolve the certificate from CurrentUser\Personal or Machine\Personal
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate to resolve</param>
        public StoreCertificateResolver(string thumbprint)
        {
            Thumbprint = thumbprint;
        }

        private string Thumbprint { get; }

        public X509Certificate2 Resolve()
        {
            return CertificateUtilities.GetClientCertificateFromStore(Thumbprint);
        }

        public ICertificateResolver Clone()
        {
            return new StoreCertificateResolver(Thumbprint);
        }

        public void Dispose()
        {
        }

        public override string ToString()
        {
            return $"thumbprint={Thumbprint}";
        }
    }

    internal class CertificateCertificateResolver : ICertificateResolver
    {
        /// <summary>
        /// Resolve the certificate from a certificate
        /// Caller is responsible for disposing the certificate
        /// </summary>
        /// <param name="certificate">The certificate instance will be copied, caller is responsible for disposing certificate</param>
        public CertificateCertificateResolver(X509Certificate certificate)
        {
            Certificate = new X509Certificate2(certificate);
        }

        private X509Certificate2 Certificate { get; }

        public X509Certificate2 Resolve()
        {
            return new X509Certificate2(Certificate);
        }

        public ICertificateResolver Clone()
        {
            return new CertificateCertificateResolver(Certificate);
        }

        public void Dispose()
        {
            Certificate?.Dispose();
        }

        public override string ToString()
        {
            return $"thumbprint={Certificate?.Thumbprint}";
        }
    }
}
