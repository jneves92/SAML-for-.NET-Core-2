using ComponentSpace.Saml2.Metadata;
using ComponentSpace.Saml2.Metadata.Compare;
using ComponentSpace.Saml2.Utility;
using ComponentSpace.Saml2.XmlSecurity;
using ComponentSpace.Saml2.XmlSecurity.Signature;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace CheckForMetadataUpdates
{
    /// <summary>
    /// Checks to see whether a partner's SAML metadata has changed.
    /// 
    /// Usage: dotnet CheckForMetadataUpdates.dll <command> <url> [-c <certificateFileName>]
    /// 
    /// where the command is check, delete or list,
    /// the URL is the endpoint for downloading the metadata,
    /// and the certificate is used to verify signed metadata.
    /// 
    /// A small database is used to keep track of metadata changes.
    /// 
    /// Entries in this database may be listed and deleted using the list and delete command respectively.
    /// 
    /// For example, to list all entries in the database:
    /// 
    /// dotnet CheckForMetadataUpdates.dll list
    /// 
    /// To list details for a specific entry in the database, identified by the SAML metadata download URL:
    /// 
    /// dotnet CheckForMetadataUpdates.dll list <url>
    /// 
    /// To delete an entry from the database, identified by the SAML metadata download URL:
    /// 
    /// dotnet CheckForMetadataUpdates.dll delete <url>
    /// 
    /// To check SAML metadata and download it if it's changed:
    /// 
    /// dotnet CheckForMetadataUpdates.dll check <url> [-c <certificateFileName>]
    /// </summary>
    class Program
    {
        private static class CommandNames
        {
            public const string Check = "check";
            public const string Delete = "delete";
            public const string List = "list";
        }

        private static class HttpHeaders
        {
            public const string IfNoneMatch = "If-None-Match";
        }

        private const string connectionString = "Data Source=MetadataRecords.db";

        private const string metadataFileName = "metadata.xml";
        private const string oldMetadataFileName = "old-metadata.xml";
        private const string newMetadataFileName = "new-metadata.xml";

        private const string certificateFilePreamble = "-----BEGIN CERTIFICATE-----";
        private const string certificateFilePostamble = "-----END CERTIFICATE-----";

        private static readonly MetadataContext metadataContext =
            new MetadataContext(new DbContextOptionsBuilder<MetadataContext>().UseSqlite(connectionString).Options);

        static void Main(string[] args)
        {
            try
            {
                metadataContext.Database.EnsureCreated();

                var commandLineApplication = new CommandLineApplication()
                {
                    Name = "CheckForMetadataUpdates",
                    Description = "Checks to see whether a partner's SAML metadata has changed"
                };

                commandLineApplication.HelpOption("-? | -h | --help");

                var commandArgument = commandLineApplication.Argument(
                    "command",
                    "The command to perform - check, list, delete");

                var urlArgument = commandLineApplication.Argument(
                    "url",
                    "The URL of the SAML metadata to check");

                var certificateOption = commandLineApplication.Option(
                    "-c | --certificate <certificateFileName>",
                    "The certificate file is used to verify signed metadata",
                    CommandOptionType.SingleValue);

                commandLineApplication.OnExecute(async () =>
                {
                    if (string.IsNullOrEmpty(commandArgument.Value))
                    {
                        Console.WriteLine("The command is missing.");
                        commandLineApplication.ShowHelp();

                        return -1;
                    }

                    switch (commandArgument.Value)
                    {
                        case CommandNames.Check:
                            if (string.IsNullOrEmpty(urlArgument.Value))
                            {
                                Console.WriteLine("The URL is missing.");
                                commandLineApplication.ShowHelp();

                                return -1;
                            }

                            await CheckForMetadataUpdatesAsync(urlArgument.Value, certificateOption.Value());
                            break;

                        case CommandNames.Delete:
                            if (string.IsNullOrEmpty(urlArgument.Value))
                            {
                                Console.WriteLine("The URL is missing.");
                                commandLineApplication.ShowHelp();

                                return -1;
                            }

                            await DeleteMetadataRecordAsync(urlArgument.Value);
                            break;

                        case CommandNames.List:
                            ListMetadataRecords(urlArgument.Value);
                            break;

                        default:
                            Console.WriteLine($"The command {commandArgument.Value} is unrecognized.");
                            commandLineApplication.ShowHelp();

                            return -1;
                    }

                    return 0;
                });

                commandLineApplication.Execute(args);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static async Task CheckForMetadataUpdatesAsync(string url, string certificateFileName)
        {
            Console.WriteLine($"Checking for SAML metadata updates at {url}.");

            var serviceCollection = new ServiceCollection();

            serviceCollection.AddLogging();
            serviceCollection.AddSaml();

            var serviceProvider = serviceCollection.BuildServiceProvider();
            var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
            var samlSchemaValidator = serviceProvider.GetRequiredService<ISamlSchemaValidator>();
            var xmlSignature = serviceProvider.GetRequiredService<IXmlSignature>();
            var metadataComparer = serviceProvider.GetRequiredService<IMetadataComparer>();

            var metadataRecord = metadataContext.MetadataRecords.SingleOrDefault(m => m.Url == url);
            var existingRecord = metadataRecord is not null;

            if (metadataRecord is null)
            {
                Console.WriteLine("There is no previous SAML metadata to compare against.");

                metadataRecord = new MetadataRecord()
                {
                    Url = url
                };
            }

            var metadataHasChanged = false;

            var oldMetadata = metadataRecord.Metadata;
            var oldHash = metadataRecord.Hash;

            metadataRecord.LastChecked = DateTime.UtcNow;

            await DownloadMetadataAsync(httpClientFactory, metadataRecord);

            if (existingRecord && metadataRecord.LastDownloaded >= metadataRecord.LastChecked)
            {
                metadataHasChanged = string.Compare(metadataRecord.Hash, oldHash, StringComparison.OrdinalIgnoreCase) != 0;

                if (metadataHasChanged)
                {
                    Console.WriteLine("The SAML metadata has changed.");

                    File.WriteAllText(oldMetadataFileName, oldMetadata);
                    Console.WriteLine($"The old SAML metadata has been saved to {oldMetadataFileName}.");

                    File.WriteAllText(newMetadataFileName, metadataRecord.Metadata);
                    Console.WriteLine($"The new SAML metadata has been saved to {newMetadataFileName}.");

                    ArgumentNullException.ThrowIfNull(oldMetadata);
                    ArgumentNullException.ThrowIfNull(metadataRecord.Metadata);

                    var oldMetadataElement = LoadMetadata(oldMetadata);
                    var newMetadataElement = LoadMetadata(metadataRecord.Metadata);

                    ValidateMetadata(samlSchemaValidator, newMetadataElement);

                    using var x509Certificate = LoadOptionalCertificate(certificateFileName);

                    VerifySignature(newMetadataElement, x509Certificate, xmlSignature);

                    var oldEntitiesDescriptor = LoadMetadata(oldMetadataElement);
                    var newEntitiesDescriptor = LoadMetadata(newMetadataElement);

                    var metadataChanges = metadataComparer.CompareMetadata(oldEntitiesDescriptor, newEntitiesDescriptor);

                    if (metadataChanges != null && metadataChanges.Count > 0)
                    {
                        metadataRecord.LastChanged = DateTime.UtcNow;

                        ShowMetadataChanges(metadataChanges);
                    }
                    else
                    {
                        Console.WriteLine($"The SAML metadata changes aren't significant and can be ignored.");
                    }
                }
                else
                {
                    Console.WriteLine($"The SAML metadata hasn't changed.");
                }
            }

            if (!existingRecord)
            {
                metadataRecord.LastChanged = DateTime.UtcNow;

                File.WriteAllText(metadataFileName, metadataRecord.Metadata);
                Console.WriteLine($"The SAML metadata has been saved to {metadataFileName}.");

                await metadataContext.MetadataRecords.AddAsync(metadataRecord);
            }

            await metadataContext.SaveChangesAsync();

            if (!existingRecord || metadataHasChanged)
            {
                Console.WriteLine($"The SAML metadata record has been saved.");
            }
        }

        private static async Task DeleteMetadataRecordAsync(string url)
        {
            Console.WriteLine($"Deleting the SAML metadata record for {url}.");

            var metadataRecord = metadataContext.MetadataRecords.SingleOrDefault(m => m.Url == url);

            if (metadataRecord is null)
            {
                Console.WriteLine("There is no SAML metadata record to delete.");
            }
            else
            {
                metadataContext.MetadataRecords.Remove(metadataRecord);
                await metadataContext.SaveChangesAsync();

                Console.WriteLine("The SAML metadata record has been deleted.");
            }
        }

        private static void ListMetadataRecords(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                foreach (var metadataRecord in metadataContext.MetadataRecords.AsNoTracking())
                {
                    Console.WriteLine(metadataRecord.Url);
                }
            }
            else
            {
                var metadataRecord = metadataContext.MetadataRecords.AsNoTracking().SingleOrDefault(m => m.Url == url);

                if (metadataRecord == null)
                {
                    Console.WriteLine($"There is no SAML metadata record for {url}.");
                }
                else
                {
                    Console.WriteLine($"URL: {url}");
                    Console.WriteLine($"Last Checked: {metadataRecord.LastChecked?.ToLocalTime()}");
                    Console.WriteLine($"Last Downloaded: {metadataRecord.LastDownloaded?.ToLocalTime()}");
                    Console.WriteLine($"Last Changed: {metadataRecord.LastChanged?.ToLocalTime()}");

                    File.WriteAllText(metadataFileName, metadataRecord.Metadata);
                    Console.WriteLine($"The SAML metadata has been saved to {metadataFileName}.");
                }
            }
        }

        private static async Task DownloadMetadataAsync(IHttpClientFactory httpClientFactory, MetadataRecord metadataRecord)
        {
            Console.WriteLine("Downloading the SAML metadata.");

            ArgumentNullException.ThrowIfNull(metadataRecord.Url);

            var requestMessage = new HttpRequestMessage()
            {
                RequestUri = new Uri(metadataRecord.Url),
                Method = HttpMethod.Get,
            };

            if (!string.IsNullOrEmpty(metadataRecord.Etag))
            {
                requestMessage.Headers.Add(HttpHeaders.IfNoneMatch, metadataRecord.Etag);
            }

            if (metadataRecord.LastDownloaded.HasValue)
            {
                requestMessage.Headers.IfModifiedSince = new DateTimeOffset(metadataRecord.LastDownloaded.Value);
            }

            var httpClient = httpClientFactory.CreateClient();

            var responseMessage = await httpClient.SendAsync(requestMessage);

            metadataRecord.Etag = responseMessage.Headers.ETag?.Tag;

            switch (responseMessage.StatusCode)
            {
                case HttpStatusCode.OK:
                    metadataRecord.Metadata = await responseMessage.Content.ReadAsStringAsync();
                    metadataRecord.Hash = ComputeHash(metadataRecord.Metadata);
                    metadataRecord.LastDownloaded = DateTime.UtcNow;

                    Console.WriteLine("The SAML metadata has been successfully downloaded.");
                    break;

                case HttpStatusCode.NotModified:
                    Console.WriteLine($"A 304 status indicates the SAML metadata hasn't changed since {metadataRecord.LastDownloaded?.ToLocalTime()}.");
                    break;

                default:
                    Console.WriteLine($"An unexpected status code ({responseMessage.StatusCode}) was returned.");
                    break;
            }
        }

        private static string ComputeHash(string contentToHash)
        {
            using SHA256 sha256 = SHA256.Create();

            return Convert.ToHexString(sha256.ComputeHash(Encoding.UTF8.GetBytes(contentToHash)));
        }

        private static XmlElement LoadMetadata(string metadataText)
        {
            var xmlDocument = new XmlDocument()
            {
                PreserveWhitespace = true
            };

            xmlDocument.LoadXml(metadataText);

            ArgumentNullException.ThrowIfNull(xmlDocument.DocumentElement);

            return xmlDocument.DocumentElement;
        }

        private static EntitiesDescriptor LoadMetadata(XmlElement xmlElement)
        {
            if (EntitiesDescriptor.IsValid(xmlElement))
            {
                return new EntitiesDescriptor(xmlElement);
            }

            if (EntityDescriptor.IsValid(xmlElement))
            {
                var entitiesDescriptor = new EntitiesDescriptor();

                entitiesDescriptor.EntityDescriptors.Add(new EntityDescriptor(xmlElement));

                return entitiesDescriptor;
            }

            throw new Exception($"The XML with element {xmlElement.Name} isn't SAML metadata.");
        }

        private static bool ValidateMetadata(ISamlSchemaValidator samlSchemaValidator, XmlElement metadataElement)
        {
            if (samlSchemaValidator.Validate(metadataElement))
            {
                Console.WriteLine("The SAML metadata XML validated against the SAML XML Schema.");
                return true;
            }

            Console.WriteLine("The SAML metadata XML failed to validate against the SAML XML Schema but errors are being ignored.");

            foreach (var errorMessage in samlSchemaValidator.Errors)
            {
                Console.WriteLine($"    Error: {errorMessage}");
            }

            foreach (var warningMessage in samlSchemaValidator.Errors)
            {
                Console.WriteLine($"    Warning: {warningMessage}");
            }

            return false;
        }

        private static void VerifySignature(XmlElement xmlElement, X509Certificate2? x509Certificate, IXmlSignature xmlSignature)
        {
            if (XmlSecurityUtility.IsSigned(xmlElement))
            {
                bool verified = false;

                using (var publicKey = x509Certificate?.GetPublicAsymmetricAlgorithm())
                {
                    verified = xmlSignature.Verify(xmlElement, publicKey);
                }

                if (verified)
                {
                    if (x509Certificate is not null)
                    {
                        Console.WriteLine("The SAML metadata signature verified using the supplied X.509 certificate.");
                    }
                    else
                    {
                        Console.WriteLine("The SAML metadata signature verified using the embedded X.509 certificate.");
                    }
                }
                else
                {
                    Console.WriteLine("The SAML metadata signature failed to verify.");

                    if (x509Certificate is not null)
                    {
                        Console.WriteLine($"Supplied certificate: Subject={x509Certificate.Subject}, Serial Number={x509Certificate.SerialNumber}, Thumbprint={x509Certificate.Thumbprint}");
                    }

                    var certificateBytes = XmlSecurityUtility.GetCertificate(xmlElement);

                    if (certificateBytes is not null)
                    {
                        var embeddedX509Certificate = new X509Certificate2(certificateBytes);

                        Console.WriteLine($"Embedded certificate: Subject={embeddedX509Certificate.Subject}, Serial Number={embeddedX509Certificate.SerialNumber}, Thumbprint={embeddedX509Certificate.Thumbprint}");

                        if (x509Certificate is not null && x509Certificate.Thumbprint != embeddedX509Certificate.Thumbprint)
                        {
                            Console.WriteLine("The wrong certificate is being used for the verification.");
                        }
                        else
                        {
                            Console.WriteLine("The XML has been altered after signing.");
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("The SAML metadata isn't signed.");
            }
        }

        private static X509Certificate2? LoadOptionalCertificate(string certificateFileName)
        {
            if (string.IsNullOrEmpty(certificateFileName))
            {
                return null;
            }

            if (!File.Exists(certificateFileName))
            {
                throw new ArgumentException($"The certificate file {certificateFileName} doesn't exist.");
            }

            return new X509Certificate2(certificateFileName);
        }

        private static void SaveCertificate(string fileName, string certificateString)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.AppendLine(certificateFilePreamble);
            stringBuilder.AppendLine(Regex.Replace(certificateString, "(.{80})", "$1" + Environment.NewLine));
            stringBuilder.AppendLine(certificateFilePostamble);

            File.WriteAllText(fileName, stringBuilder.ToString());
        }

        private static void ShowMetadataChanges(IList<MetadataChange> metadataChanges)
        {
            foreach (var metadataChange in metadataChanges)
            {
                switch (metadataChange.ChangeType)
                {
                    /// <summary>
                    /// The entityID has changed.
                    /// </summary>
                    case MetadataChangeType.EntityIdChanged:
                        Console.WriteLine($"The entity ID has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The number of metadata items has changed.
                    /// </summary>
                    case MetadataChangeType.ItemCountChanged:
                        Console.WriteLine($"The {metadataChange.Context} count has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The WantAuthnRequestsSigned flag has changed.
                    /// </summary>
                    case MetadataChangeType.WantAuthnRequestsSignedChanged:
                        Console.WriteLine($"The {metadataChange.Context} WantAuthnRequestsSigned flag has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The WantAssertionsSigned flag has changed.
                    /// </summary>
                    case MetadataChangeType.WantAssertionsSignedChanged:
                        Console.WriteLine($"The {metadataChange.Context} WantAssertionsSigned flag has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The key descriptor Use has changed.
                    /// </summary>
                    case MetadataChangeType.KeyDescriptorUseChanged:
                        Console.WriteLine($"The {metadataChange.Context} use has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The X.509 certificate has changed.
                    /// </summary>
                    case MetadataChangeType.CertificateChanged:
                        var oldX509Certificate = new X509Certificate2(Convert.FromBase64String(metadataChange.OldMetadata));
                        var newX509Certificate = new X509Certificate2(Convert.FromBase64String(metadataChange.NewMetadata));

                        Console.WriteLine($"The X.509 certificate with serial number {oldX509Certificate.SerialNumber} has been replaced with the X.509 certificate with serial number {newX509Certificate.SerialNumber}.");

                        var fileName = $"{newX509Certificate.SerialNumber}.cer";

                        SaveCertificate(fileName, metadataChange.NewMetadata);
                        Console.WriteLine($"The new certificate has been saved to {fileName}.");

                        break;

                    /// <summary>
                    /// The location has changed for the endpoint.
                    /// </summary>
                    case MetadataChangeType.EndpointLocationChanged:
                        Console.WriteLine($"The {metadataChange.Context} endpoint location has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The response location has changed for the endpoint.
                    /// </summary>
                    case MetadataChangeType.EndpointResponseLocationChanged:
                        Console.WriteLine($"The {metadataChange.Context} endpoint response location has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The binding has changed for the endpoint.
                    /// </summary>
                    case MetadataChangeType.EndpointBindingChanged:
                        Console.WriteLine($"The {metadataChange.Context} endpoint binding has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The index has changed for the endpoint.
                    /// </summary>
                    case MetadataChangeType.EndpointIndexChanged:
                        Console.WriteLine($"The {metadataChange.Context} endpoint index has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    /// <summary>
                    /// The isDefault flag has changed for the endpoint.
                    /// </summary>
                    case MetadataChangeType.EndpointDefaultFlagChanged:
                        Console.WriteLine($"The {metadataChange.Context} endpoint default flag has changed from {metadataChange.OldMetadata} to {metadataChange.NewMetadata}.");
                        break;

                    default:
                        Console.WriteLine($"The metadata change {metadataChange.ChangeType} occurred.");
                        break;
                }
            }
        }
    }
}
