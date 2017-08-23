using AspNet.Security.OAuth.AWSCognito;
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class AWSCognitoExtensions
	{
		public static AuthenticationBuilder AddAWSCognito(
			this AuthenticationBuilder builder,
			string authenticationScheme,
			string displayName,
			Action<AWSCognitoOptions> configureOptions
			)
			=> builder.AddOAuth<AWSCognitoOptions, AWSCognitoHandler>(authenticationScheme, displayName, configureOptions);
	}
}
