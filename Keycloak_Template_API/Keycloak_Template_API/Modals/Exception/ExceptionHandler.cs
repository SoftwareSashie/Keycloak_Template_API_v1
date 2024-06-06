using System;
using System.Text.Json.Serialization;

namespace Keycloak_Template_API.Modals.Exception
{
	public class ExceptionHandler
	{
        [JsonPropertyName("Method")]
        public required string Method { get; set; }

        [JsonPropertyName("ErrorMessage")]
        public required string ErrorMessage { get; set; }
    }
}

