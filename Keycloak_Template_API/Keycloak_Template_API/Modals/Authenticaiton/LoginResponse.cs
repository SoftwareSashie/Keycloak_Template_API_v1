using System;
using System.Text.Json.Serialization;

namespace Keycloak_Template_API.Modals.Authenticaiton
{
	public class LoginResponse
	{
        [JsonPropertyName("accessToken")]
        public required string accessToken { get; set; }

        [JsonPropertyName("refreshToken")]
        public required string refreshToken { get; set; }

        [JsonPropertyName("expiresIn")]
        public int expiresIn { get; set; }
    }
}

