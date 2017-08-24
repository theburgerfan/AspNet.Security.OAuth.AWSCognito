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
		// https://XXXXXXXXXXX.auth.REGIONLOWERCASE.amazoncognito.com

		public AWSCognitoOptions()
		{
			Scope.Add(AWSCognitoScopes.AwsCognitoSigninUserAdmin);

			// AWS Cognito claims
			// http://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html
			ClaimActions.MapJsonKey(ClaimTypes.StreetAddress, "address");
			ClaimActions.MapJsonKey(ClaimTypes.DateOfBirth, "birthdate");
			ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
			ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
			ClaimActions.MapJsonKey(ClaimTypes.Gender, "gender");
			ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
			ClaimActions.MapJsonKey(ClaimTypes.Locality, "locale");
			ClaimActions.MapJsonKey("MiddleName", "middle_name");
			ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
			ClaimActions.MapJsonKey("Nickname", "nickname");
			ClaimActions.MapJsonKey(ClaimTypes.HomePhone, "phone_number");
			ClaimActions.MapJsonKey("Picture", "picture");
			ClaimActions.MapJsonKey("PreferredName", "preferred_username");
			ClaimActions.MapJsonKey("Profile", "profile");
			ClaimActions.MapJsonKey("Timezone", "timezone");
			ClaimActions.MapJsonKey("Timezone", "timezone");
			ClaimActions.MapJsonKey("UpdatedAt", "updated_at");
			ClaimActions.MapJsonKey(ClaimTypes.Webpage, "website");

			// UserId
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
