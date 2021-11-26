using Azure.Security.KeyVault.Certificates;
using KeyVaultCertificateProvider.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("KeyVaultCertificateProvider.Tests")]
namespace KeyVaultCertificateProvider.StorageProvider.KeyVault.Parser
{
    internal class PemCertificateParser : IParser
    {
        public static CertificateContentType ContentType => CertificateContentType.Pem;

        public CertificateResponse Parse(StorageResponse storageResponse)
        {
            string certificate = string.IsNullOrEmpty(storageResponse.PrivatePart) ?
                storageResponse.PublicPart :
                storageResponse.PrivatePart;

            var privateKeyBuilder = new StringBuilder();
            var publicKeys = new List<StringBuilder>();

            using var reader = new StringReader(certificate);
            StringBuilder currentKeyBuilder = null;

            Regex regexCertKey = new Regex("(-)*(BEGIN)(.*)(PRIVATE KEY)(-)*");
            Regex regexCertBegin = new Regex("(-)*(BEGIN)(.*)(CERTIFICATE)(-)*");
            string line = reader.ReadLine();
            while (line != null)
            {
                if (regexCertKey.IsMatch(line))
                {
                    currentKeyBuilder = privateKeyBuilder;
                }
                else if (regexCertBegin.IsMatch(line))
                {
                    var publicKeyBuilder = new StringBuilder();
                    publicKeys.Add(publicKeyBuilder);

                    currentKeyBuilder = publicKeyBuilder;
                }
                else if (currentKeyBuilder is null)
                {
                    throw new InvalidOperationException("Invalid PEM-encoded certificate.");
                }

                currentKeyBuilder.AppendLine(line);

                line = reader.ReadLine();
            }

            return new CertificateResponse
            {
                Certificates = string.Join(string.Empty, publicKeys).Trim(),
                PrivateKey = privateKeyBuilder.ToString().Trim()
            };
        }
    }
}
