using ComponentSpace.Saml2.Certificates;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Validates an X.509 certificate.
/// 
/// Usage: dotnet ValidateCert.dll <fileName> [-p <password>]
/// 
/// where the file contains an X.509 certificate to be validated.
/// </summary>
try
{
    var commandLineApplication = new CommandLineApplication()
    {
        Name = "ValidateCert",
        Description = "Validates an X.509 certificate"
    };

    commandLineApplication.HelpOption("-? | -h | --help");

    var fileNameArgument = commandLineApplication.Argument(
        "fileName",
        "The X.509 certificate to be validated");

    var passwordOption = commandLineApplication.Option(
        "-p | --password <password>",
        "The certificate file password",
        CommandOptionType.SingleValue);

    commandLineApplication.OnExecute(() =>
    {
        if (string.IsNullOrEmpty(fileNameArgument.Value))
        {
            Console.WriteLine("The file name is missing.");
            commandLineApplication.ShowHelp();

            return -1;
        }

        ValidateCert(fileNameArgument.Value, passwordOption.Value());

        return 0;
    });

    commandLineApplication.Execute(args);
}

catch (Exception exception)
{
    Console.WriteLine(exception.ToString());
}

static void ValidateCert(string fileName, string password)
{
    if (!File.Exists(fileName))
    {
        throw new ArgumentException($"The file {fileName} doesn't exist.");
    }

    var x509Certificate = new X509Certificate2(fileName, password, X509KeyStorageFlags.EphemeralKeySet);

    var serviceCollection = new ServiceCollection();

    serviceCollection.AddLogging(builder =>
    {
        builder.SetMinimumLevel(LogLevel.Debug);
        builder.AddConsole();
    });

    serviceCollection.Configure<CertificateValidationOptions>(options =>
    {
        options.EnableChainCheck = true;
    });

    serviceCollection.AddSaml();

    using var serviceProvider = serviceCollection.BuildServiceProvider();

    foreach (var certificateValidator in serviceProvider.GetServices<ICertificateValidator>())
    {
        certificateValidator.Validate(x509Certificate);
    }
}
