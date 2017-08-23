using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Runtime;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.AWSCognito
{
	internal class AWSCognitoHandler : OAuthHandler<AWSCognitoOptions>
	{
		private AmazonCognitoIdentityProviderClient m_amazonCognitoIdentityProviderClient = null;
		protected AmazonCognitoIdentityProviderClient CognitoIdentityProviderClient
		{
			get
			{
				if (m_amazonCognitoIdentityProviderClient == null)
				{
					m_amazonCognitoIdentityProviderClient = new AmazonCognitoIdentityProviderClient(
						new AnonymousAWSCredentials(),
						Options.AmazonRegionEndpoint);
				}
				return m_amazonCognitoIdentityProviderClient;
			}
		}

		public AWSCognitoHandler(IOptionsMonitor<AWSCognitoOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base(options, logger, encoder, clock)
		{
		}

		protected override async Task<AuthenticationTicket> CreateTicketAsync(
			ClaimsIdentity identity,
			AuthenticationProperties properties,
			OAuthTokenResponse tokens)
		{
			// Get user from AWS Cognito
			var response = await CognitoIdentityProviderClient.GetUserAsync(new GetUserRequest()
			{
				AccessToken = tokens.AccessToken
			}, Context.RequestAborted);

			if (response.HttpStatusCode != System.Net.HttpStatusCode.OK)
			{
				throw new HttpRequestException($"An error occurred when retrieving user information ({response.HttpStatusCode}).");
			}

			string userAsJson = Newtonsoft.Json.JsonConvert.SerializeObject(response.UserAttributes.ToDictionary(x => x.Name, x => x.Value));
			var payload = JObject.Parse(userAsJson);

			var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload);
			context.RunClaimActions();

			await Events.CreatingTicket(context);
			return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
		}

		protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
		{
			// AWS Cognito Authorization Endpoint
			// http://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html

			var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			queryStrings.Add("response_type", "code");
			queryStrings.Add("client_id", Options.ClientId);
			queryStrings.Add("redirect_uri", redirectUri);

			AddQueryString(queryStrings, properties, "scope", FormatScope());

			var state = Options.StateDataFormat.Protect(properties);
			queryStrings.Add("state", state);

			var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
			return authorizationEndpoint;
		}

		private static void AddQueryString(
			IDictionary<string, string> queryStrings,
			AuthenticationProperties properties,
			string name,
			string defaultValue = null)
		{
			string value;
			if (!properties.Items.TryGetValue(name, out value))
			{
				value = defaultValue;
			}
			else
			{
				// Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
				properties.Items.Remove(name);
			}

			if (value == null)
			{
				return;
			}

			queryStrings[name] = value;
		}

		protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
		{
			// AWS Cognito Token Endpoint
			// http://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html

			var tokenRequestParameters = new Dictionary<string, string>()
			{
				{ "client_id", Options.ClientId },
				{ "redirect_uri", redirectUri },
				{ "code", code },
				{ "grant_type", "authorization_code" },
			};

			var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

			var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
			requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
			requestMessage.Headers.Add("Authorization", $"Basic {System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{Options.ClientId}:{Options.ClientSecret}"))}");
			requestMessage.Content = requestContent;
			var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);
			if (response.IsSuccessStatusCode)
			{
				var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
				return OAuthTokenResponse.Success(payload);
			}
			else
			{
				var error = "OAuth token endpoint failure: " + await Display(response);
				return OAuthTokenResponse.Failed(new Exception(error));
			}
		}

		protected static async Task<string> Display(HttpResponseMessage response)
		{
			var output = new StringBuilder();
			output.Append("Status: " + response.StatusCode + ";");
			output.Append("Headers: " + response.Headers.ToString() + ";");
			output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
			return output.ToString();
		}
	}
}
