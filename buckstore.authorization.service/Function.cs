using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace buckstore.authorization.service
{
    public class Function
    {

        /// <summary>
        /// Function do authorize jwt token
        /// </summary>
        /// <param name="apigAuthRequest"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public APIGatewayCustomAuthorizerResponse FunctionHandler(APIGatewayCustomAuthorizerRequest apigAuthRequest, ILambdaContext context)
        {
            string token = apigAuthRequest.AuthorizationToken.Replace("Bearer ", string.Empty);
            var isAuthorized = false;
            var key = Encoding.ASCII.GetBytes("b665f456d3ed4bf09a56842e02de8ab7c5f5cc9c138a476e88369ce815effbb5");

            var tokenValidationParameters = new TokenValidationParameters 
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };

            var jwtHandler = new JwtSecurityTokenHandler();

            if (!string.IsNullOrWhiteSpace(token))
            {
                try
                {
                    var authorizate = jwtHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
                    isAuthorized = true;
                }

                catch (Exception e)
                {
                    LambdaLogger.Log("Erro na validação do token, Token informado é inválido" + e);
                }
            }

            return CreateApiGatewayPolicyResponse(isAuthorized, apigAuthRequest);
        }

        private APIGatewayCustomAuthorizerResponse CreateApiGatewayPolicyResponse(bool isAuthorized, APIGatewayCustomAuthorizerRequest apigAuthRequest)
        {
            APIGatewayCustomAuthorizerPolicy policy = new APIGatewayCustomAuthorizerPolicy
            {
                Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>()
            };

            policy.Statement.Add(new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement 
            {
                Action = new HashSet<string>(new string[] { "execute-api:Invoke" }),
                Effect = isAuthorized ? "Allow" : "Deny",
                Resource = new HashSet<string>(new string[] { apigAuthRequest.MethodArn })
            });

            var contextOutput = new APIGatewayCustomAuthorizerContextOutput();
            contextOutput["Path"] = apigAuthRequest.MethodArn;

            return new APIGatewayCustomAuthorizerResponse 
            {
                Context = contextOutput,
                PolicyDocument = policy
            };
        }
    }
}
