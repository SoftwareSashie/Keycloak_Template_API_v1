using System;
using System.Text.Json.Serialization;

namespace Keycloak_Template_API.Modals.Authenticaiton
{
	public class LoginRequest
	{
        [JsonPropertyName("UserName")]
        public required string UserName { get; set; }

        [JsonPropertyName("Password")]
        public required string Password { get; set; }
    }
}

