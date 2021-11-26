using AutoFixture;
using Azure.Security.KeyVault.Certificates;
using FakeItEasy;
using FluentAssertions;
using KeyVaultCertificateProvider.Models;
using KeyVaultCertificateProvider.Requests.Download;
using KeyVaultCertificateProvider.StorageProvider;
using KeyVaultCertificateProvider.StorageProvider.KeyVault.Parser;
using Serilog;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace KeyVaultCertificateProvider.Tests
{
    public class SecretsManagerTests
    {
        private ISecretsManager secretsManager;
        private readonly ILogger logger;
        private readonly IStorageProvider storageProvider;
        private readonly string storageKey;
        private Func<CertificateContentType, IParser> parserFactory;
        private readonly IFixture fixture;

        public SecretsManagerTests()
        {
            fixture = new Fixture();
            logger = A.Fake<ILogger>();
            storageProvider = A.Fake<IStorageProvider>();
            storageKey = fixture.Create<string>();

            SetupStorageProvider(storageKey);
        }

        [Fact]
        public async Task GetCertificate_SuccesfullyParsed()
        {
            secretsManager = new SecretsManager(storageProvider, parserFactory, logger);

            var request = new CertificateDownloadRequest(storageKey);

            var certificateResponse = await secretsManager.GetCertificate(request);

            certificateResponse.Certificates.Should().Contain("BEGIN CERTIFICATE");
            certificateResponse.PrivateKey.Should().Contain("PRIVATE KEY");
        }

        private void SetupStorageProvider(string storageKey)
        {
            parserFactory = (certificateType) =>
            {
                return certificateType == CertificateContentType.Pem ?
                    new PemCertificateParser() :
                    new PkcsCertificateParser();
            };

            var storageResponse = A.Fake<StorageResponse>();
            var certificatePublic = File.ReadAllText(@"Certificates\Certificate1.pem");
            var certificatePrivate = string.Join(Environment.NewLine, certificatePublic, File.ReadAllText(@"Certificates\Certificate1Key.pem"));
            A.CallTo(() => storageResponse.ContentType).Returns(CertificateContentType.Pem.ToString());
            A.CallTo(() => storageResponse.PublicPart).Returns(certificatePublic);
            A.CallTo(() => storageResponse.PrivatePart).Returns(certificatePrivate);

            A.CallTo(() => storageProvider.DownloadCertificateAsync(storageKey)).Returns(storageResponse);
        }
    }
}
