using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace OneIdentity.SafeguardDotNet
{
    internal static class CertificateUtilities
    {
        public static X509Certificate2 GetClientCertificateFromStore(string thumbprint)
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    var cert = GetClientCertificateFromStore(thumbprint, store);
                    if (cert != null) return cert;
                }
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    var cert = GetClientCertificateFromStore(thumbprint, store);
                    if (cert != null) return cert;
                }
                throw new SafeguardDotNetException("Unable to find certificate matching " +
                                                   $"thumbprint={thumbprint} in Computer or User store");
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from thumbprint={thumbprint}", ex);
            }
        }

        internal static X509Certificate2 GetClientCertificateFromStore(string thumbprint, X509Store store)
        {
            store.Open(OpenFlags.ReadOnly);
            foreach (var cert in store.Certificates)
            {
                if (string.IsNullOrEmpty(cert.Thumbprint)) continue;
                if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }
            return null;
        }

        public static X509Certificate2 GetClientCertificateFromFile(string filepath, SecureString password)
        {
            try
            {
                return new X509Certificate2(filepath, password);
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from file={filepath}", ex);
            }
        }
    }
}
