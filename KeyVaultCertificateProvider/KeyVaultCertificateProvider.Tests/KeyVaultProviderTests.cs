using AutoFixture;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using FakeItEasy;
using FluentAssertions;
using KeyVaultCertificateProvider.Models;
using KeyVaultCertificateProvider.Requests.Upload;
using KeyVaultCertificateProvider.StorageProvider.KeyVault;
using Serilog;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace KeyVaultCertificateProvider.Tests
{
    public class KeyVaultProviderTests
    {
        private readonly KeyVaultProvider _keyVaultProvider;
        private readonly CertificateClient _certificateClient;
        private readonly SecretClient _secretClient;
        private readonly ILogger _logger;
        private readonly IFixture _fixture;

        public KeyVaultProviderTests()
        {
            _certificateClient = A.Fake<CertificateClient>();
            _secretClient = A.Fake<SecretClient>();
            _logger = A.Fake<ILogger>();

            _fixture = new Fixture();

            _keyVaultProvider = new KeyVaultProvider(_certificateClient,
                _secretClient,
                _logger);
        }

        [Fact]
        public async Task DownloadCertificateAsync_ShouldSuccesfullyDownload()
        {
            var certificateName = "certificateKey";

            var secretName = _fixture.Create<string>();
            var secretVersion = _fixture.Create<string>();
            var secretUri = new Uri($"https://{Guid.NewGuid()}.vault.azure.net/secrets/{secretName}/{secretVersion}");
            var certContent = _fixture.Create<byte[]>();

            var kvCertificate = CertificateModelFactory.KeyVaultCertificateWithPolicy(CertificateModelFactory.CertificateProperties(), secretId: secretUri, cer: certContent);
            var kvCertResponse = Response.FromValue(kvCertificate, A.Fake<Response>());

            var kvSecret = SecretModelFactory.KeyVaultSecret(new SecretProperties(nameof(SecretProperties)) { ContentType = CertificateContentType.Pkcs12.ToString() }, Convert.ToBase64String(certContent));
            var kvSecretResponse = Response.FromValue(kvSecret, A.Fake<Response>());

            var expectedResponse = new KeyVaultResponse(kvCertificate, kvSecret);

            A.CallTo(() => _certificateClient.GetCertificateAsync(certificateName, A<CancellationToken>._)).Returns(kvCertResponse);
            A.CallTo(() => _secretClient.GetSecretAsync(secretName, secretVersion, A<CancellationToken>._)).Returns(kvSecretResponse);

            var actual = await _keyVaultProvider.DownloadCertificateAsync(certificateName);

            actual.Should().BeEquivalentTo(expectedResponse);
        }

        [Fact]
        public async Task DownloadCertificateAsync_ShouldThrowException()
        {
            var certificateName = "certificateKey";

            A.CallTo(() => _certificateClient.GetCertificateAsync(certificateName, A<CancellationToken>._)).Throws(new Exception());

            var actual = await _keyVaultProvider.DownloadCertificateAsync(certificateName);

            actual.Should().BeNull();
        }

        [Fact]
        public async Task UploadCertificateAsync_ShouldSuccesfullyUpload()
        {
            byte[] randomBytes = new byte[100];

            var random = new Random();
            random.NextBytes(randomBytes);

            var kvCertificate = CertificateModelFactory.KeyVaultCertificateWithPolicy(CertificateModelFactory.CertificateProperties());

            var request = new CertificateUploadRequest(Convert.ToBase64String(randomBytes), _fixture.Create<string>(), _fixture.Create<string>());
            var azureResponse = A.Fake<Response>();

            A.CallTo(() => azureResponse.Status).Returns(200);

            var response = Response.FromValue(kvCertificate, azureResponse);

            A.CallTo(() => _certificateClient.ImportCertificateAsync(A<ImportCertificateOptions>._, A<CancellationToken>._)).Returns(response);

            var actual = await _keyVaultProvider.UploadCertificateAsync(request.CertificateStorageKey, request.PublicCertificates, request.PrivateKey);

            actual.Should().BeTrue();
        }

        [Fact]
        public async Task UploadCertificateAsync_ShouldThrowException()
        {
            byte[] randomBytes = new byte[100];

            var random = new Random();
            random.NextBytes(randomBytes);

            var request = new CertificateUploadRequest(Convert.ToBase64String(randomBytes), _fixture.Create<string>(), _fixture.Create<string>());

            A.CallTo(() => _certificateClient.ImportCertificateAsync(A<ImportCertificateOptions>._, A<CancellationToken>._)).Throws(new Exception());

            var actual = await _keyVaultProvider.UploadCertificateAsync(request.CertificateStorageKey, request.PublicCertificates, request.PrivateKey);

            actual.Should().BeFalse();
        }
    }
}
