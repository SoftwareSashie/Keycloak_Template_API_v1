using System;
using System.IdentityModel.Tokens.Jwt;
using Keycloak_Template_API.Modals.Authenticaiton;

namespace Keycloak_Template_API.Interfaces
{
	public interface IAuthenticationService
	{
        Task<LoginResponse> ApplicationLogin(LoginRequest applicationLoginRequest);

        Task<bool> ApplicationLogout(string refreshToken);

        bool ApplicationTokenValidation(string token, out JwtSecurityToken validatedToken);

        Task<LoginResponse> ApplicationRefresh(string refreshToken);
    }
}

