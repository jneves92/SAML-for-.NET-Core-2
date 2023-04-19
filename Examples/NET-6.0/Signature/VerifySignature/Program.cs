using ComponentSpace.Saml2;
using ComponentSpace.Saml2.Protocols;
using ComponentSpace.Saml2.Utility;
using ComponentSpace.Saml2.XmlSecurity;
using ComponentSpace.Saml2.XmlSecurity.Signature;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

/// <summary>
/// Verifies XML signatures on SAML v2.0 assertions, messages and metadata.
/// 
/// Usage: dotnet VerifySignature.dll <fileName> [-c <certificateFileName>]
/// 
/// where the file contains a SAML assertion, message or metadata XML.
/// 
/// XML signatures are verified using the public key associated with the X.509 certificate.
/// </summary>
try
{
    var commandLineApplication = new CommandLineApplication()
    {
        Name = "VerifySignature",
        Description = "Verifies an XML signature on a SAML assertion, message or metadata"
    };

    commandLineApplication.HelpOption("-? | -h | --help");

    var fileNameArgument = commandLineApplication.Argument(
        "fileName",
        "The XML file containing the signed SAML assertion, message or metadata");

    var certificateOption = commandLineApplication.Option(
        "-c | --certificate <certificateFileName>",
        "The optional certificate file used to verify the signature",
        CommandOptionType.SingleValue);

    commandLineApplication.OnExecute(() =>
    {
        if (string.IsNullOrEmpty(fileNameArgument.Value))
        {
            Console.WriteLine("The file name is missing.");
            commandLineApplication.ShowHelp();

            return -1;
        }

        VerifySignature(fileNameArgument.Value, certificateOption.Value());

        return 0;
    });

    commandLineApplication.Execute(args);
}

catch (Exception exception)
{
    Console.WriteLine(exception.ToString());
}

static void VerifySignature(string fileName, string certificateFileName)
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

    var serviceCollection = new ServiceCollection();

    serviceCollection.AddLogging();
    serviceCollection.AddSaml();

    var serviceProvider = serviceCollection.BuildServiceProvider();
    var xmlSignature = serviceProvider.GetRequiredService<IXmlSignature>();

    using var x509Certificate = LoadOptionalCertificate(certificateFileName);

    switch (xmlDocument?.DocumentElement?.NamespaceURI)
    {
        case SamlConstants.NamespaceUris.Assertion:
            VerifyAssertionSignature(xmlDocument.DocumentElement, x509Certificate, xmlSignature);
            break;

        case SamlConstants.NamespaceUris.Protocol:
            VerifyMessageSignature(xmlDocument.DocumentElement, x509Certificate, xmlSignature);
            break;

        case SamlConstants.NamespaceUris.Metadata:
            VerifyMetadataSignature(xmlDocument.DocumentElement, x509Certificate, xmlSignature);
            break;

        default:
            throw new ArgumentException($"Unexpected namespace URI: {xmlDocument?.DocumentElement?.NamespaceURI}");
    }
}

static X509Certificate2? LoadOptionalCertificate(string certificateFileName)
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

static void VerifyAssertionSignature(XmlElement xmlElement, X509Certificate2? x509Certificate, IXmlSignature xmlSignature)
{
    Console.WriteLine("Verifying the SAML assertion signature.");
    VerifyXmlSignature(xmlElement, x509Certificate, xmlSignature);
}

static void VerifyMessageSignature(XmlElement xmlElement, X509Certificate2? x509Certificate, IXmlSignature xmlSignature)
{
    Console.WriteLine("Verifying the SAML message signature.");
    VerifyXmlSignature(xmlElement, x509Certificate, xmlSignature);

    if (SamlResponse.IsValid(xmlElement))
    {
        var samlResponse = new SamlResponse(xmlElement);

        foreach (var samlAssertionElement in samlResponse.GetSignedAssertions())
        {
            VerifyAssertionSignature(samlAssertionElement, x509Certificate, xmlSignature);
        }
    }
}

static void VerifyMetadataSignature(XmlElement xmlElement, X509Certificate2? x509Certificate, IXmlSignature xmlSignature)
{
    Console.Error.WriteLine("Verifying the SAML metadata signature.");
    VerifyXmlSignature(xmlElement, x509Certificate, xmlSignature);
}

static void VerifyXmlSignature(XmlElement xmlElement, X509Certificate2? x509Certificate, IXmlSignature xmlSignature)
{
    if (XmlSecurityUtility.IsSigned(xmlElement))
    {
        bool verified = false;

        using (var publicKey = x509Certificate?.GetPublicAsymmetricAlgorithm())
        {
            verified = xmlSignature.Verify(xmlElement, publicKey);
        }

        Console.WriteLine($"Signature verified: {verified}");
        Console.WriteLine($"Signature algorithm: {XmlSecurityUtility.GetSignatureAlgorithm(xmlElement)}");

        if (!verified)
        {
            if (x509Certificate != null)
            {
                Console.WriteLine($"Supplied certificate: Subject={x509Certificate.Subject}, Serial Number={x509Certificate.SerialNumber}, Thumbprint={x509Certificate.Thumbprint}");
            }

            var certificateBytes = XmlSecurityUtility.GetCertificate(xmlElement);

            if (certificateBytes != null)
            {
                var embeddedX509Certificate = new X509Certificate2(certificateBytes);

                Console.WriteLine($"Embedded certificate: Subject={embeddedX509Certificate.Subject}, Serial Number={embeddedX509Certificate.SerialNumber}, Thumbprint={embeddedX509Certificate.Thumbprint}");

                if (x509Certificate != null && x509Certificate.Thumbprint != embeddedX509Certificate.Thumbprint)
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
        Console.WriteLine("The XML isn't signed.");
    }
}
