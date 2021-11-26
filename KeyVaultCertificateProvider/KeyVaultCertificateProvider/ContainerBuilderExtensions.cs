using Autofac;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using KeyVaultCertificateProvider.StorageProvider.KeyVault;
using KeyVaultCertificateProvider.StorageProvider.KeyVault.Parser;
using System;

namespace KeyVaultCertificateProvider
{
    public static class ContainerBuilderExtensions
    {
        public static void RegisterSecretVault(this ContainerBuilder builder, Uri vaultUri, TokenCredential credential)
        {
            builder
                .RegisterInstance(new CertificateClient(vaultUri, credential))
                .SingleInstance();

            builder
                .RegisterInstance(new SecretClient(vaultUri, credential))
                .SingleInstance();

            builder
                .RegisterType<PkcsCertificateParser>()
                .Keyed<IParser>(PkcsCertificateParser.ContentType)
                .AsImplementedInterfaces();

            builder
                .RegisterType<PemCertificateParser>()
                .Keyed<IParser>(PemCertificateParser.ContentType)
                .AsImplementedInterfaces();

            builder
                .RegisterType<KeyVaultProvider>()
                .AsImplementedInterfaces();

            builder.Register<Func<CertificateContentType, IParser>>(componentContext =>
            {
                return (certType) =>
                {
                    var certParser = componentContext.ResolveKeyed<IParser>(certType);

                    return certParser;
                };
            });

            builder
                .RegisterType<SecretsManager>()
                .AsImplementedInterfaces()
                .InstancePerDependency();
        }
    }
}