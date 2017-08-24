using Amazon;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace AspNet.Security.OAuth.AWSCognito
{
	/// <summary>
	/// Configuration options for <see cref="AWSCognitoHandler"/>.
	/// </summary>
	public class AWSCognitoOptions : OAuthOptions
	{
		public RegionEndpoint AmazonRegionEndpoint { get; set; } = RegionEndpoint.USEast1;

		// todo : automate AuthorizationEndpoint and TokenEndpoint by taking UserPoolDomainPrefix and assembling the urls

		public AWSCognitoOptions()
		{
			Scope.Add(AWSCognitoScopes.AwsCognitoSigninUserAdmin);

			ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
			ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
			ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
			ClaimActions.MapCustomJson(ClaimTypes.NameIdentifier, (json) =>
			{
				JToken token;
				if (json.TryGetValue("identities", out token))
				{
					JArray identities = JArray.Parse(token.ToString());
					foreach (JToken identity in identities)
					{
						if (JObject.Parse(identity.ToString()).TryGetValue("userId", out token))
						{
							return token.Value<string>();
						}
					}
				}
				return null;
			});
		}
	}
}
