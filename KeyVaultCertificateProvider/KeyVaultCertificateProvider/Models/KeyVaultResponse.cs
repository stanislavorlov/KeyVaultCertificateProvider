using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System;

namespace KeyVaultCertificateProvider.Models
{
    public class KeyVaultResponse : StorageResponse
    {
        public KeyVaultResponse(KeyVaultCertificateWithPolicy publicPart, KeyVaultSecret privatePart)
        {
            PublicPart = Convert.ToBase64String(publicPart.Cer);
            PrivatePart = privatePart.Value;
            ContentType = privatePart.Properties.ContentType;
        }
    }
}
