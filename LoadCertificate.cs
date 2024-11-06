using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace FuncKvRepro
{
    public class LoadCertificate
    {
        private readonly ILogger<LoadCertificate> _logger;
        private const string environmentVariable = "the-cert";

        public LoadCertificate(ILogger<LoadCertificate> logger)
        {
            _logger = logger;
        }

        [Function("LoadCertificate")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequest req)
        {
            IActionResult result = null;
            var envVariableValue = Environment.GetEnvironmentVariable(environmentVariable);

            if (string.IsNullOrEmpty(envVariableValue))
            {
                _logger.LogError(new ArgumentException("null or empty environment variable"), $"Environment variable {environmentVariable} is not set."))
            }

            try
            {
                var cert = new X509Certificate2(Convert.FromBase64String(envVariableValue));

                // Create an MD5 hash of the environment variable value.  Assign the hash to a variablle
                // named certHash
                var certHash = string.Empty;
                using var md5 = MD5.Create();
                var inputBytes = Encoding.ASCII.GetBytes(envVariableValue);
                var hashBytes = md5.ComputeHash(inputBytes);
                var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
                result = new OkObjectResult(new {message = $"Hash is {hash}"});
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to load certificate");
                result = new BadRequestResult();
            }

            _logger.LogInformation("C# HTTP trigger function processed a request.");
            return result;
        }
    }
}
