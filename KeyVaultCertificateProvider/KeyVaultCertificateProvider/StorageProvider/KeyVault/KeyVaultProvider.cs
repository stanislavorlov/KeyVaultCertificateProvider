using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using KeyVaultCertificateProvider.Models;
using Serilog;
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultCertificateProvider.StorageProvider.KeyVault
{
    public class KeyVaultProvider : IStorageProvider
    {
        private readonly CertificateClient _certificateClient;
        private readonly SecretClient _secretClient;
        private readonly ILogger _logger;

        public KeyVaultProvider(CertificateClient certificateClient, SecretClient secretClient, ILogger logger)
        {
            _certificateClient = certificateClient;
            _secretClient = secretClient;
            _logger = logger;
        }

        public async Task<StorageResponse> DownloadCertificateAsync(string certificateName)
        {
            try
            {
                var kvCertificateResponse = await _certificateClient.GetCertificateAsync(certificateName);
                var identifier = new KeyVaultSecretIdentifier(kvCertificateResponse.Value.SecretId);
                Response<KeyVaultSecret> secretResponse = await _secretClient.GetSecretAsync(identifier.Name, identifier.Version);

                return new KeyVaultResponse(kvCertificateResponse.Value, secretResponse.Value);
            }
            catch (Exception exc)
            {
                _logger.Error(exc, $"Failed to fetch certificate: {certificateName}");

                return null;
            }
        }

        public async Task<bool> UploadCertificateAsync(string certificateName, string publicKey, string privateKey)
        {
            try
            {
                var certificateContent = new StringBuilder();
                certificateContent.AppendLine(privateKey);
                certificateContent.AppendLine(publicKey);

                var importCertificateOptions = new ImportCertificateOptions(certificateName, Encoding.UTF8.GetBytes(certificateContent.ToString()));

                var operationResponse = await _certificateClient.ImportCertificateAsync(importCertificateOptions);

                return operationResponse.GetRawResponse().Status == (int)HttpStatusCode.OK;
            }
            catch (Exception exc)
            {
                _logger.Error(exc, $"Failed to upload certificate: {certificateName}");

                return false;
            }
        }

        public async Task<string> GetSecretAsync(string secretKey)
        {
            try
            {
                var secretResponse = await _secretClient.GetSecretAsync(secretKey);

                return secretResponse.Value.Value;
            }
            catch (Exception exc)
            {
                _logger.Error(exc, $"Failed to fetch secret from key vault by key: {secretKey}");

                return null;
            }
        }

        public async Task<string> SetSecretAsync(string secretKey, string secretValue)
        {
            try
            {
                var operationResponse = await _secretClient.SetSecretAsync(secretKey, secretValue);

                return operationResponse.Value.Value;
            }
            catch (Exception exc)
            {
                _logger.Error(exc, $"Failed to set secret to key vault for: {secretKey}");

                return null;
            }
        }
    }
}
