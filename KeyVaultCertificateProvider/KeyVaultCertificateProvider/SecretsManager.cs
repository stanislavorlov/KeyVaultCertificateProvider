using Azure.Security.KeyVault.Certificates;
using KeyVaultCertificateProvider.Models;
using KeyVaultCertificateProvider.Requests.Download;
using KeyVaultCertificateProvider.StorageProvider;
using KeyVaultCertificateProvider.StorageProvider.KeyVault.Parser;
using Serilog;
using System;
using System.Threading.Tasks;

namespace KeyVaultCertificateProvider
{
    public class SecretsManager : ISecretsManager
    {
        private readonly ILogger _logger;
        private readonly IStorageProvider _storageProvider;
        private readonly Func<CertificateContentType, IParser> _parserFactory;

        public SecretsManager(
            IStorageProvider storageProvider,
            Func<CertificateContentType, IParser> parserFactory,
            ILogger logger)
        {
            _logger = logger;
            _storageProvider = storageProvider;
            _parserFactory = parserFactory;
        }

        public async Task<CertificateResponse> GetCertificate(CertificateDownloadRequest certificateRequest)
        {
            try
            {
                var storageResponse = await _storageProvider.DownloadCertificateAsync(certificateRequest.CertificateStorageKey);

                var parser = _parserFactory(storageResponse.ContentType);

                return parser.Parse(storageResponse);
            }
            catch (Exception exc)
            {
                _logger.Error(exc, $"Faild to fetch certificate by key: {certificateRequest.CertificateStorageKey}");

                return null;
            }
        }
    }
}
