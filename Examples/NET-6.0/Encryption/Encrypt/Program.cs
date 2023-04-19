using ComponentSpace.Saml2;
using ComponentSpace.Saml2.Assertions;
using ComponentSpace.Saml2.XmlSecurity.Encryption;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

/// <summary>
/// Encrypts SAML v2.0 assertions, attributes and IDs.
/// 
/// Usage: dotnet Encrypt.dll <fileName> [-k <keyAlgorithm>] [-d <dataAlgorithm>] -c <certificateFileName> [-o <outputFileName>]
/// 
/// where the file contains a SAML assertion, attribute or ID,
/// the key encryption method defaults to http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
/// and the data encryption method defaults to "http://www.w3.org/2001/04/xmlenc#aes256-cbc".
/// 
/// SAML assertions attributes and IDs are encrypted using the public key associated with the X.509 certificate.
/// </summary>
try
{
    var commandLineApplication = new CommandLineApplication()
    {
        Name = "Encrypt",
        Description = "Encrypts a SAML assertion, attribute or ID"
    };

    commandLineApplication.HelpOption("-? | -h | --help");

    var fileNameArgument = commandLineApplication.Argument(
        "fileName",
        "The XML file containing a SAML assertion, attribute or ID");

    var keyAlgorithmOption = commandLineApplication.Option(
        "-k | --keyAlgorithm <keyAlgorithm>",
        "The key encryption algorithm",
        CommandOptionType.SingleValue);

    var dataAlgorithmOption = commandLineApplication.Option(
        "-d | --dataAlgorithm <dataAlgorithm>",
        "The data encryption algorithm",
        CommandOptionType.SingleValue);

    var certificateOption = commandLineApplication.Option(
        "-c | --certificate <certificateFileName>",
        "The certificate file used to encrypt the assertion, attribute or ID",
        CommandOptionType.SingleValue);

    var outputOption = commandLineApplication.Option(
        "-o | --output <outputFileName>",
        "The generated XML file containing the encrypted assertion, attribute or ID",
        CommandOptionType.SingleValue);

    commandLineApplication.OnExecute(() =>
    {
        if (string.IsNullOrEmpty(fileNameArgument.Value))
        {
            Console.WriteLine("The file name is missing.");
            commandLineApplication.ShowHelp();

            return -1;
        }

        if (string.IsNullOrEmpty(certificateOption.Value()))
        {
            Console.WriteLine("The certificate file name is missing.");
            commandLineApplication.ShowHelp();

            return -1;
        }

        Encrypt(fileNameArgument.Value, keyAlgorithmOption.Value(), dataAlgorithmOption.Value(), certificateOption.Value(), outputOption.Value());

        return 0;
    });

    commandLineApplication.Execute(args);
}

catch (Exception exception)
{
    Console.WriteLine(exception.ToString());
}

static void Encrypt(string fileName, string keyAlgorithm, string dataAlgorithm, string certificateFileName, string outputFileName)
{
    if (!File.Exists(fileName))
    {
        throw new ArgumentException($"The file {fileName} doesn't exist.");
    }

    var xmlDocument = new XmlDocument
    {
        PreserveWhitespace = true
    };

    xmlDocument.Load(fileName);

    if (!File.Exists(certificateFileName))
    {
        throw new ArgumentException($"The certificate file {certificateFileName} doesn't exist.");
    }

    if (string.IsNullOrEmpty(keyAlgorithm))
    {
        keyAlgorithm = SamlConstants.KeyEncryptionAlgorithms.RSA_OAEP_MGF1P;
    }

    if (string.IsNullOrEmpty(dataAlgorithm))
    {
        dataAlgorithm = SamlConstants.DataEncryptionAlgorithms.AES_256;
    }

    var serviceCollection = new ServiceCollection();

    serviceCollection.AddLogging();
    serviceCollection.AddSaml();

    var serviceProvider = serviceCollection.BuildServiceProvider();
    var xmlEncryption = serviceProvider.GetRequiredService<IXmlEncryption>();

    using var x509Certificate = new X509Certificate2(certificateFileName);
    using var publicKey = x509Certificate.GetRSAPublicKey();

    XmlElement encryptedDataElement = xmlEncryption.Encrypt(
        xmlDocument.DocumentElement,
        publicKey,
        keyAlgorithm,
        dataAlgorithm,
        x509Certificate);

    if (xmlDocument?.DocumentElement?.NamespaceURI != SamlConstants.NamespaceUris.Assertion)
    {
        throw new ArgumentException($"Unexpected namespace URI: {xmlDocument?.DocumentElement?.NamespaceURI}");
    }

    var encryptedXmlDocument = new XmlDocument()
    {
        PreserveWhitespace = true
    };

    XmlElement encryptedElement;

    switch (xmlDocument.DocumentElement.LocalName)
    {
        case ElementNames.Assertion:
            var encryptedAssertion = new EncryptedAssertion()
            {
                EncryptedData = encryptedDataElement
            };

            encryptedElement = encryptedAssertion.ToXml(encryptedXmlDocument);
            break;

        case ElementNames.Attribute:
            var encryptedAttribute = new EncryptedAttribute()
            {
                EncryptedData = encryptedDataElement
            };

            encryptedElement = encryptedAttribute.ToXml(encryptedXmlDocument);
            break;

        case ElementNames.NameID:
            var encryptedID = new EncryptedID()
            {
                EncryptedData = encryptedDataElement
            };

            encryptedElement = encryptedID.ToXml(encryptedXmlDocument);
            break;

        case ElementNames.NewID:
            var newEncryptedID = new NewEncryptedID()
            {
                EncryptedData = encryptedDataElement
            };

            encryptedElement = newEncryptedID.ToXml(encryptedXmlDocument);
            break;

        default:
            throw new ArgumentException($"Unexpected element name: {xmlDocument.DocumentElement.LocalName}");
    }

    if (string.IsNullOrEmpty(outputFileName))
    {
        outputFileName = fileName;
    }

    encryptedXmlDocument.AppendChild(encryptedElement);
    encryptedElement.OwnerDocument.Save(outputFileName);
}

static class ElementNames
{
    public const string Assertion = "Assertion";
    public const string Attribute = "Attribute";
    public const string NameID = "NameID";
    public const string NewID = "NewID";
}
