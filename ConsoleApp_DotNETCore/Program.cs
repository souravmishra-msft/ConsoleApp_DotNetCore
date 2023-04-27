using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using System;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ConsoleApp_DotNETCore
{
    internal class Program
    {
        private static PublicClientApplicationOptions appConfiguration = null;
        private static IConfiguration configuration;
        private static IPublicClientApplication app;

        private static async Task Main(string[] args)
        {
            configuration = new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            appConfiguration = configuration
                               .Get<PublicClientApplicationOptions>();

            string[] scopes = new[] {"user.read"};
            await CallUserDetails(appConfiguration, scopes);
        }

        private static async Task<string> SignInUserAndGetTokenUsingMSAL(PublicClientApplicationOptions configuration, string[] scopes)
        {
            string authority = string.Concat(configuration.Instance, configuration.TenantId);

            app = PublicClientApplicationBuilder.Create(configuration.ClientId)
                                                .WithAuthority(authority)
                                                .WithDefaultRedirectUri()
                                                .Build();

            AuthenticationResult result;
            
            try
            {
                var accounts = await app.GetAccountsAsync();
                result = await app.AcquireTokenSilent(scopes, accounts.FirstOrDefault()).ExecuteAsync();
            }
            catch(MsalUiRequiredException ex)
            {
                var accounts = await app.GetAccountsAsync();
                result = await app.AcquireTokenInteractive(scopes)
                    .WithAccount(accounts.FirstOrDefault())

                    .ExecuteAsync();
            }

            //Convert the claims to a dictionary
            var claimsDictionary = new Dictionary<string, object>();
            foreach (var claim in result.ClaimsPrincipal.Claims)
            {
                claimsDictionary[claim.Type] = claim.Value;
            }


            var userDetailsJson = JsonSerializer.Serialize(claimsDictionary);

            return userDetailsJson;
        }

        private static async Task CallUserDetails(PublicClientApplicationOptions configuration, string[] scopes)
        {
            var userClaimsJson = await SignInUserAndGetTokenUsingMSAL(configuration, scopes);

            //Deserialize the JSON to a dictionary
            var userClaimsDict = JsonSerializer.Deserialize<Dictionary<string, object>>(userClaimsJson);

            //Extract all the claims
            var id = userClaimsDict["oid"]?.ToString();
            var displayName = userClaimsDict["name"]?.ToString();
            var firstName = userClaimsDict["given_name"]?.ToString();
            var lastName = userClaimsDict["family_name"]?.ToString();
            var email = userClaimsDict["email"]?.ToString(); 

            // Printing the results
            Console.WriteLine("-------- Data from ID-Token Claims --------");
            Console.Write(Environment.NewLine);
            Console.WriteLine($"Id           : {id}");
            Console.WriteLine($"Display Name : {displayName}");
            Console.WriteLine($"First Name   : {firstName}");
            Console.WriteLine($"Last Name    : {lastName}");
            Console.WriteLine($"Email        : {email}");
            Console.Write(Environment.NewLine);
            Console.WriteLine("-------------------- End -------------------");
        }

    }
}
