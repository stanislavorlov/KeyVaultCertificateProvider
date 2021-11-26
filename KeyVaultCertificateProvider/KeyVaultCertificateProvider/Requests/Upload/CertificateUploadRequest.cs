namespace KeyVaultCertificateProvider.Requests.Upload
{
    public class CertificateUploadRequest
    {
        public string CertificateStorageKey { get; }

        public string PublicCertificates { get; }
        public string PrivateKey { get; }

        public CertificateUploadRequest(string certificates, string privateKey, string storageKey)
        {
            PublicCertificates = certificates;
            PrivateKey = privateKey;
            CertificateStorageKey = storageKey;
        }
    }
}
