using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json.Serialization;

namespace Keycloak_Template_API.Modals.Authenticaiton
{
	public class TokenValidity
	{
        [JsonPropertyName("IsValid")]
        public bool IsValid { get; set; }

        [JsonPropertyName("validatedToken")]
        public JwtSecurityToken? validatedToken { get; set; }
    }
}

