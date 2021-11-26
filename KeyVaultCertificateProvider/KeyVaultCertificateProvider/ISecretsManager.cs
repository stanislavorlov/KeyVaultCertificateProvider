using KeyVaultCertificateProvider.Models;
using KeyVaultCertificateProvider.Requests.Download;
using System.Threading.Tasks;

namespace KeyVaultCertificateProvider
{
    public interface ISecretsManager
    {
        Task<CertificateResponse> GetCertificate(CertificateDownloadRequest certificateRequest);
    }
}