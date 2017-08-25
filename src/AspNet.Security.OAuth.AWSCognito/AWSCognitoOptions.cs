using Amazon;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Security.Claims;

namespace AspNet.Security.OAuth.AWSCognito
{
	/// <summary>
	/// Configuration options for <see cref="AWSCognitoHandler"/>.
	/// </summary>
	public class AWSCognitoOptions : OAuthOptions
	{
		private string m_userPoolAppDomainPrefix;

		/// <summary>
		/// Amazon Region containing the AWS Cognito User Pool
		/// </summary>
		public RegionEndpoint AmazonRegionEndpoint { get; set; } = RegionEndpoint.USEast1;

		/// <summary>
		/// Domain Prefix of the AWS Cognito User Pool Application
		/// </summary>
		public string UserPoolAppDomainPrefix
		{
			get
			{
				return m_userPoolAppDomainPrefix;
			}
			set
			{
				m_userPoolAppDomainPrefix = value;
				AuthorizationEndpoint = $"{BaseUserPoolApplicationDomain}/authorize";
				TokenEndpoint = $"{BaseUserPoolApplicationDomain}/token";
			}
		}

		/// <summary>
		/// Gets the URI where the client will be redirected to authenticate.
		/// </summary>
		public new string AuthorizationEndpoint
		{
			get
			{
				return base.AuthorizationEndpoint;
			}

			private set
			{
				base.AuthorizationEndpoint = value;
			}
		}

		/// <summary>
		/// Gets the URI the middleware will access to exchange the OAuth token.
		/// </summary>
		public new string TokenEndpoint
		{
			get
			{
				return base.TokenEndpoint;
			}

			private set
			{
				base.TokenEndpoint = value;
			}
		}

		private string BaseUserPoolApplicationDomain
		{
			get
			{
				return $"https://{UserPoolAppDomainPrefix}.auth.{AmazonRegionEndpoint.SystemName}.amazoncognito.com";
			}
		}

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

		public override void Validate()
		{
			base.Validate();

			if (string.IsNullOrEmpty(UserPoolAppDomainPrefix))
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", nameof(UserPoolAppDomainPrefix)), nameof(UserPoolAppDomainPrefix));
			}
		}
	}
}
