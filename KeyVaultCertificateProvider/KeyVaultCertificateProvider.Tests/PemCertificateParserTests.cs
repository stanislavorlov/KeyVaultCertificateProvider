using AutoFixture;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using FakeItEasy;
using KeyVaultCertificateProvider.Models;
using System;
using System.IO;
using System.Text;
using Xunit;

namespace KeyVaultCertificateProvider.Tests
{
    public class PemCertificateParserTests
    {
        private readonly IFixture _fixture;

        public PemCertificateParserTests()
        {
            _fixture = new Fixture();
        }

        [Theory]
        [InlineData("Certificate1.pem", "Certificate1Key.pem")]
        [InlineData("Certificate2.pem", "Certificate2Key.pem")]
        public void ParsePemFileShouldParse(string cert, string key)
        {
            var secretName = _fixture.Create<string>();
            var secretVersion = _fixture.Create<string>();
            var secretUri = new Uri($"https://{Guid.NewGuid()}.vault.azure.net/secrets/{secretName}/{secretVersion}");
            var certContent = File.ReadAllText(@$"Certificates\{cert}");
            var keyContent = string.Empty;
            if (!string.IsNullOrEmpty(key))
            {
                keyContent = File.ReadAllText($@"Certificates\{key}");
            }
            var fileContent = Encoding.UTF8.GetBytes(string.Join(Environment.NewLine, certContent, keyContent));

            var kvCertificate = CertificateModelFactory.KeyVaultCertificateWithPolicy(CertificateModelFactory.CertificateProperties(), secretId: secretUri, cer: Encoding.UTF8.GetBytes(certContent));
            var kvCertResponse = Response.FromValue(kvCertificate, A.Fake<Response>());

            var kvSecret = SecretModelFactory.KeyVaultSecret(new SecretProperties(nameof(SecretProperties)) { ContentType = CertificateContentType.Pkcs12.ToString() }, Convert.ToBase64String(fileContent));
            var kvSecretResponse = Response.FromValue(kvSecret, A.Fake<Response>());

            var storageResponse = new KeyVaultResponse(kvCertificate, kvSecret);

            Assert.NotNull(storageResponse);
            Assert.NotNull(storageResponse.ContentType);
            Assert.NotNull(storageResponse.PublicPart);
        }
    }
}
