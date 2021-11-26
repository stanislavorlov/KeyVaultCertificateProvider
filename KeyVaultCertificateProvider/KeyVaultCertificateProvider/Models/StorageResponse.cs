namespace KeyVaultCertificateProvider.Models
{
    public abstract class StorageResponse
    {
        public virtual string PublicPart { get; protected set; }
        public virtual string PrivatePart { get; protected set; }
        public virtual string ContentType { get; protected set; }
    }
}
