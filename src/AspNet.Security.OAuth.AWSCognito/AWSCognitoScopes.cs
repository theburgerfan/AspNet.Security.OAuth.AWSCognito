using System;
using System.Collections.Generic;
using System.Text;

namespace AspNet.Security.OAuth.AWSCognito
{
    public class AWSCognitoScopes
    {
		// todo : additional non-custom scopes
		public const string OpenId = "openid";
		public const string Profile = "profile";
		public const string Email = "email";
		public const string AwsCognitoSigninUserAdmin = "aws.cognito.signin.user.admin";
	}
}
