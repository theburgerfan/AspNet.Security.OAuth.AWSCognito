# ASP.Net Core 2.0 OAuth Provider for AWS Cognito

**AspNet.Security.OAuth.AWSCognito** allows you to authenticate against your AWS Cognito User Pool. This can be handy if your User Pool is associated with [Social Identity Providers](http://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-social.html) such as Facebook or Google.

Information about using Amazon Cognito User Pools can be found at [http://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html](http://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html)

## Dependencies

* [AWSSDK.CognitoIdentityProvider](https://www.nuget.org/packages/AWSSDK.CognitoIdentityProvider/) - used to retrieve the user claims information
* [Microsoft.AspNetCore.Authentication.OAuth](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.OAuth/) - This Provider is subclassed from the OAuth Provider

## Getting Started

Once you have [set up your Amazon Cognito User Pool](http://docs.aws.amazon.com/cognito/latest/developerguide/getting-started-with-cognito-user-pools.html) and [defined an application within the user pool](http://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-integration.html), you will have the necessary information to configure this provider.

In your `Startup` class `ConfigureServices` method, register the Provider and configure it 

```csharp

    services.AddAuthentication()
        .AddAWSCognito(
            My-AuthenticationScheme-Name,
            My-Auth-DisplayName,
            options =>
            {
                options.ClientId = "YOUR_USERPOOL_APP_CLIENT_ID";
                options.ClientSecret = "YOUR_USERPOOL_APP_CLIENT_SECRET";
                
                options.CallbackPath = new PathString("/signin-myservice"); // Your UserPool App Callback Url
                options.AuthorizationEndpoint = "https://<YOUR-USERPOOL-APP-DOMAIN-PREFIX>.auth.us-east-1.amazoncognito.com/authorize";
                options.TokenEndpoint = "https://<YOUR-USERPOOL-APP-DOMAIN-PREFIX>.auth.us-east-1.amazoncognito.com/token";
                options.AmazonRegionEndpoint = RegionEndpoint.USEast1; // AWS Region of your Cognito User Pool
                
                // Add Your Scopes of Interest
                options.Scope.Add(AWSCognitoScopes.OpenId);
                options.Scope.Add(AWSCognitoScopes.Profile);
                options.Scope.Add(AWSCognitoScopes.Email);
                options.Scope.Add(AWSCognitoScopes.AwsCognitoSigninUserAdmin);
            });

```
