using ComponentSpace.Saml2;
using ComponentSpace.Saml2.Utility;
using ComponentSpace.Saml2.XmlSecurity;
using ComponentSpace.Saml2.XmlSecurity.Signature;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

/// <summary>
/// Generates XML signatures on SAML v2.0 assertions, messages and metadata.
/// 
/// Usage: dotnet GenerateSignature.dll <fileName> [-d <digestAlgorithm>] [-s <signatureAlgorithm>] -c <certificateFileName> -p <password> [-o <outputFileName>]
/// 
/// where the file contains a SAML assertion, message or metadata XML.
/// 
/// XML signatures are generated using the private key associated with the X.509 certificate.
/// </summary>
try
{
    var commandLineApplication = new CommandLineApplication()
    {
        Name = "GenerateSignature",
        Description = "Generates an XML signature on a SAML assertion, message or metadata"
    };

    commandLineApplication.HelpOption("-? | -h | --help");

    var fileNameArgument = commandLineApplication.Argument(
        "fileName",
        "The XML file containing a SAML assertion, message or metadata");

    var digestAlgorithmOption = commandLineApplication.Option(
        "-d | --digestAlgorithm <digestAlgorithm>",
        "The digest algorithm",
        CommandOptionType.SingleValue);

    var signatureAlgorithmOption = commandLineApplication.Option(
        "-s | --signatureAlgorithm <signatureAlgorithm>",
        "The signature algorithm",
        CommandOptionType.SingleValue);

    var certificateOption = commandLineApplication.Option(
        "-c | --certificate <certificateFileName>",
        "The certificate file used to generate the signature",
        CommandOptionType.SingleValue);

    var passwordOption = commandLineApplication.Option(
        "-p | --password <password>",
        "The certificate file password",
        CommandOptionType.SingleValue);

    var outputOption = commandLineApplication.Option(
        "-o | --output <outputFileName>",
        "The generated XML file containing the signed SAML assertion, message or metadata",
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

        if (string.IsNullOrEmpty(passwordOption.Value()))
        {
            Console.WriteLine("The certificate file password is missing.");
            commandLineApplication.ShowHelp();

            return -1;
        }

        GenerateSignature(fileNameArgument.Value, digestAlgorithmOption.Value(), signatureAlgorithmOption.Value(), certificateOption.Value(), passwordOption.Value(), outputOption.Value());

        return 0;
    });

    commandLineApplication.Execute(args);
}

catch (Exception exception)
{
    Console.WriteLine(exception.ToString());
}

static void GenerateSignature(string fileName, string digestAlgorithm, string signatureAlgorithm, string certificateFileName, string certificatePassword, string outputFileName)
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

    if (string.IsNullOrEmpty(digestAlgorithm))
    {
        digestAlgorithm = SamlConstants.DigestAlgorithms.SHA256;
    }

    if (string.IsNullOrEmpty(signatureAlgorithm))
    {
        signatureAlgorithm = SamlConstants.SignatureAlgorithms.RSA_SHA256;
    }

    var serviceCollection = new ServiceCollection();

    serviceCollection.AddLogging();
    serviceCollection.AddSaml();

    var serviceProvider = serviceCollection.BuildServiceProvider();
    var xmlSignature = serviceProvider.GetRequiredService<IXmlSignature>();

    using (var x509Certificate = new X509Certificate2(certificateFileName, certificatePassword))
    {
        switch (xmlDocument?.DocumentElement?.NamespaceURI)
        {
            case SamlConstants.NamespaceUris.Assertion:
                GenerateAssertionSignature(xmlDocument.DocumentElement, x509Certificate, digestAlgorithm, signatureAlgorithm, xmlSignature);
                break;

            case SamlConstants.NamespaceUris.Protocol:
                GenerateMessageSignature(xmlDocument.DocumentElement, x509Certificate, digestAlgorithm, signatureAlgorithm, xmlSignature);
                break;

            case SamlConstants.NamespaceUris.Metadata:
                GenerateMetadataSignature(xmlDocument.DocumentElement, x509Certificate, digestAlgorithm, signatureAlgorithm, xmlSignature);
                break;

            default:
                throw new ArgumentException($"Unexpected namespace URI: {xmlDocument?.DocumentElement?.NamespaceURI}");
        }
    }

    if (string.IsNullOrEmpty(outputFileName))
    {
        outputFileName = fileName;
    }

    xmlDocument.Save(outputFileName);
}

static void GenerateAssertionSignature(XmlElement xmlElement, X509Certificate2 x509Certificate, string digestAlgorithm, string signatureAlgorithm, IXmlSignature xmlSignature)
{
    Console.WriteLine("Generating the SAML assertion signature.");

    var signatureElement = GenerateXmlSignature(
        xmlElement,
        x509Certificate,
        digestAlgorithm,
        signatureAlgorithm,
        SamlConstants.InclusiveNamespacesPrefixLists.Assertion,
        xmlSignature);

    xmlElement.InsertAfter(signatureElement, xmlElement.FirstChild);
}

static void GenerateMessageSignature(XmlElement xmlElement, X509Certificate2 x509Certificate, string digestAlgorithm, string signatureAlgorithm, IXmlSignature xmlSignature)
{
    Console.WriteLine("Generating the SAML message signature.");

    var signatureElement = GenerateXmlSignature(
        xmlElement,
        x509Certificate,
        digestAlgorithm,
        signatureAlgorithm,
        SamlConstants.InclusiveNamespacesPrefixLists.Protocol,
        xmlSignature);

    xmlElement.InsertAfter(signatureElement, xmlElement.FirstChild);
}

static void GenerateMetadataSignature(XmlElement xmlElement, X509Certificate2 x509Certificate, string digestAlgorithm, string signatureAlgorithm, IXmlSignature xmlSignature)
{
    Console.WriteLine("Generating the SAML metadata signature.");

    var signatureElement = GenerateXmlSignature(
        xmlElement,
        x509Certificate,
        digestAlgorithm,
        signatureAlgorithm,
        SamlConstants.InclusiveNamespacesPrefixLists.Metadata,
        xmlSignature);

    xmlElement.InsertBefore(signatureElement, xmlElement.FirstChild);
}

static XmlElement GenerateXmlSignature(
    XmlElement xmlElement,
    X509Certificate2 x509Certificate,
    string digestAlgorithm,
    string signatureAlgorithm,
    string inclusiveNamespacesPrefixList,
    IXmlSignature xmlSignature)
{
    if (XmlSecurityUtility.IsSigned(xmlElement))
    {
        throw new ArgumentException("The XML is already signed.");
    }

    using var privateKey = x509Certificate.GetPrivateAsymmetricAlgorithm();

    return xmlSignature.Generate(xmlElement, privateKey, digestAlgorithm, signatureAlgorithm, inclusiveNamespacesPrefixList, x509Certificate);
}
