using KeyVaultCertificateProvider.Models;
using System.Threading.Tasks;

namespace KeyVaultCertificateProvider.StorageProvider
{
    public interface IStorageProvider
    {
        Task<StorageResponse> DownloadCertificateAsync(string certificateName);

        Task<bool> UploadCertificateAsync(string certificateName, string publicKey, string privateKey);

        Task<string> GetSecretAsync(string secretKey);

        Task<string> SetSecretAsync(string secretKey, string secretValue);
    }
}
