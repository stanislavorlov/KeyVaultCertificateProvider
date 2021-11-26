using KeyVaultCertificateProvider.Models;

namespace KeyVaultCertificateProvider.StorageProvider.KeyVault.Parser
{
    public interface IParser
    {
        CertificateResponse Parse(StorageResponse storageResponse);
    }
}
