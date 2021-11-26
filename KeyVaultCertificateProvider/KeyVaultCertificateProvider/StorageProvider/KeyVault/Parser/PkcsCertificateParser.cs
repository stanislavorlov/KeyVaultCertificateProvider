using Azure.Security.KeyVault.Certificates;
using KeyVaultCertificateProvider.Models;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("KeyVaultCertificateProvider.Tests")]
namespace KeyVaultCertificateProvider.StorageProvider.KeyVault.Parser
{
    internal class PkcsCertificateParser : IParser
    {
        const string PublicKeyFormat = "-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----";
        const string PrivateKeyFormat = "-----BEGIN PRIVATE KEY-----\n{0}\n-----END PRIVATE KEY-----";

        public static CertificateContentType ContentType = CertificateContentType.Pkcs12;

        public CertificateResponse Parse(StorageResponse storageResponse)
        {
            return new CertificateResponse
            {
                Certificates = string.Format(PublicKeyFormat, storageResponse.PublicPart),
                PrivateKey = string.Format(PrivateKeyFormat, storageResponse.PrivatePart)
            };
        }
    }
}
