using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Keycloak_Template_API.Interfaces;
using Keycloak_Template_API.Modals.Authenticaiton;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak_Template_API.Services
{
	public class AuthenticationService : IAuthenticationService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly List<RsaSecurityKey> _keys;

        public AuthenticationService(IConfiguration configuration, HttpClient httpClient)
		{
            _configuration = configuration;
            _httpClient = httpClient;

            var keycloakConfig = _configuration.GetSection("Keycloak");
            var publicKey1 = keycloakConfig["PublicKey1"];
            var publicKey2 = keycloakConfig["PublicKey2"];

            _keys = new List<RsaSecurityKey>
            {
                CreateRsaSecurityKey(publicKey1),
                CreateRsaSecurityKey(publicKey2)
            };
        }

        private RsaSecurityKey CreateRsaSecurityKey(string publicKeyPem)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            return new RsaSecurityKey(rsa);
        }

        public async Task<LoginResponse> ApplicationLogin(LoginRequest applicationLoginRequest)
        {
            try
            {

                var keycloakSettings = _configuration.GetSection("Keycloak");

                var clientId = keycloakSettings["ClientId"];
                var clientSecret = keycloakSettings["ClientSecret"];
                var realm = keycloakSettings["Realm"];
                var baseURL = keycloakSettings["AuthServerUrl"];

                if (string.IsNullOrEmpty(clientId) ||
                    string.IsNullOrEmpty(clientSecret) ||
                    string.IsNullOrEmpty(realm) ||
                    string.IsNullOrEmpty(applicationLoginRequest.UserName) ||
                    string.IsNullOrEmpty(applicationLoginRequest.Password)
                    )
                {
                    throw new ArgumentNullException($"Login serivce initial values null: clientId{clientId} - clientSecret{clientSecret} - realm{realm} UserName - {applicationLoginRequest.UserName} Password - {applicationLoginRequest.UserName}");
                }

                var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/realms/{realm}/protocol/openid-connect/token");
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("username", applicationLoginRequest.UserName),
                    new KeyValuePair<string, string>("password", applicationLoginRequest.Password)
                });

                request.Content = content;

                HttpClientHandler clientHandler = new HttpClientHandler();
                clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
                // Pass the handler to httpclient(from you are calling api)
                HttpClient client = new HttpClient(clientHandler);

                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var tokenResponse = await response.Content.ReadFromJsonAsync<KeyCloakTokenResponse>();

                var result = new LoginResponse()
                {
                    accessToken = tokenResponse.AccessToken,
                    refreshToken = tokenResponse.RefreshToken,
                    expiresIn = tokenResponse.ExpiresIn
                };

                return result;
            }
            catch (Exception ex)
            {
                var errorMessage = $"Error loggin user on Keycloak: UserName - {applicationLoginRequest.UserName}. Exception - {ex.Message}";
                throw new Exception(errorMessage);
            }
        }

        public async Task<bool> ApplicationLogout(string refreshToken)
        {
            try
            {
                var validToken = refreshToken.StartsWith("Bearer ") ? refreshToken.Substring("Bearer ".Length).Trim() : refreshToken;
                var keycloakConfig = _configuration.GetSection("Keycloak");
                var clientId = keycloakConfig["ClientId"];
                var clientSecret = keycloakConfig["ClientSecret"];
                var baseURL = keycloakConfig["AuthServerUrl"];
                var realm = keycloakConfig["Realm"];
                var logoutEndpoint = $"{baseURL}/realms/{realm}/protocol/openid-connect/logout";

                var request = new HttpRequestMessage(HttpMethod.Post, logoutEndpoint)
                {
                    Content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("client_id", clientId),
                        new KeyValuePair<string, string>("client_secret", clientSecret),
                        new KeyValuePair<string, string>("refresh_token", validToken)
                    })
                };

                request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

                HttpClientHandler clientHandler = new HttpClientHandler();
                clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
                // Pass the handler to httpclient(from you are calling api)
                HttpClient client = new HttpClient(clientHandler);

                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                return true;
            }
            catch (Exception ex)
            {
                var errorMessage = "Error logging out user";
                throw new Exception($"{errorMessage}: {ex.Message}");
            }
        }

        public async Task<LoginResponse> ApplicationRefresh(string refreshToken)
        {
            try
            {
                var keycloakConfig = _configuration.GetSection("Keycloak");
                var clientId = keycloakConfig["ClientId"];
                var clientSecret = keycloakConfig["ClientSecret"];
                var baseURL = keycloakConfig["AuthServerUrl"];
                var realm = keycloakConfig["Realm"];
                var refreshEndpoint = $"{baseURL}/realms/{realm}/protocol/openid-connect/token";

                var validToken = refreshToken.Substring("Bearer ".Length).Trim();

                var request = new HttpRequestMessage(HttpMethod.Post, refreshEndpoint)
                {
                    Content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("client_id", clientId),
                        new KeyValuePair<string, string>("client_secret", clientSecret),
                        new KeyValuePair<string, string>("grant_type", "refresh_token"),
                        new KeyValuePair<string, string>("refresh_token", validToken)
                    })
                };
                request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

                HttpClientHandler clientHandler = new HttpClientHandler();
                clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
                // Pass the handler to httpclient(from you are calling api)
                HttpClient client = new HttpClient(clientHandler);

                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var tokenResponse = await response.Content.ReadFromJsonAsync<KeyCloakTokenResponse>();

                var result = new LoginResponse()
                {
                    accessToken = tokenResponse.AccessToken,
                    refreshToken = tokenResponse.RefreshToken,
                    expiresIn = tokenResponse.ExpiresIn
                };

                return result;
            }
            catch (Exception ex)
            {
                var errorMessage = $"Error Refreshing token";
                throw new Exception(errorMessage + ex.Message);
            }
        }

        public bool ApplicationTokenValidation(string token, out JwtSecurityToken validatedToken)
        {
            try
            {
                var validToken = token.Substring("Bearer ".Length).Trim();

                var keycloakConfig = _configuration.GetSection("Keycloak");
                var issuer = keycloakConfig["Issuer"];
                var audience = keycloakConfig["Audience"];


                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidateLifetime = true,
                    IssuerSigningKeys = _keys,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero
                };

                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(validToken, validationParameters, out var securityToken);
                validatedToken = securityToken as JwtSecurityToken;
                return true;

            }
            catch (Exception ex)
            {
                validatedToken = null;
                return false;

            }
        }
    }
}

