using System;
using Keycloak_Template_API.Interfaces;
using Keycloak_Template_API.Modals.Authenticaiton;
using Keycloak_Template_API.Modals.Exception;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Keycloak_Template_API.Controllers
{
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;

        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest applicationLoginRequest)
        {
            try
            {
                var response = await _authenticationService.ApplicationLogin(applicationLoginRequest);
                return Ok(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Application Login   - {ex.Message}");
                return StatusCode(500, new ExceptionHandler
                {
                    Method = "Login - Controller",
                    ErrorMessage = $"Error loggin in user - {applicationLoginRequest.UserName}"
                });
            }
        }

        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout([FromHeader] string AuthorizationRefresh)
        {
            try
            {
                var response = await _authenticationService.ApplicationLogout(AuthorizationRefresh);
                return Ok();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Application Logout  - {ex.Message}");
                return StatusCode(500, new ExceptionHandler
                {
                    Method = "Login - Controller",
                    ErrorMessage = $"Error refreshing user token"
                });
            }
        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromHeader] string AuthorizationRefresh)
        {
            try
            {
                var response = await _authenticationService.ApplicationRefresh(AuthorizationRefresh);
                return Ok(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Application Refresh  - {ex.Message}");
                return StatusCode(500, new ExceptionHandler
                {
                    Method = "Login - Controller",
                    ErrorMessage = $"Error refreshing user token"
                });
            }
        }


        [HttpGet]
        [Route("ValidateTokenTest")]
        public IActionResult ValidateTokenTest([FromHeader] string Authorization)
        {
            try
            {
                var validity = tokenValidity(Authorization);
                if (!validity.IsValid)
                {
                    return Unauthorized();
                }

                return Ok();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validating token - {ex.Message}");
                return StatusCode(500, new ExceptionHandler
                {
                    Method = "Login - ValidateTokenTest",
                    ErrorMessage = $"Error validating token"
                });
            }
        }


        private TokenValidity tokenValidity(string Authorization)
        {
            var tokenValidity = new TokenValidity();

            if (string.IsNullOrEmpty(Authorization) || !Authorization.StartsWith("Bearer "))
            {
                tokenValidity.IsValid = false;
                return tokenValidity;
            }

            var isTokenValid = _authenticationService.ApplicationTokenValidation(Authorization, out var validatedToken);
            tokenValidity.IsValid = isTokenValid;
            tokenValidity.validatedToken = validatedToken;

            return tokenValidity;
        }
    }
}

