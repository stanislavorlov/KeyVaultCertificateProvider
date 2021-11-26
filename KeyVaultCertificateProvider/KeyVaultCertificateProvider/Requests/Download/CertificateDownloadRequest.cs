namespace KeyVaultCertificateProvider.Requests.Download
{
    public class CertificateDownloadRequest
    {
        public string CertificateStorageKey { get; }

        public CertificateDownloadRequest(string key)
        {
            CertificateStorageKey = key;
        }
    }
}