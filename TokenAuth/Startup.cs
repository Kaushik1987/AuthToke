using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using Microsoft.Owin.Security.OAuth;

[assembly: OwinStartup(typeof(TokenAuth.Startup))]

namespace TokenAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder appBuilder)
        {
            HttpConfiguration httpConfiguration = new HttpConfiguration();
            appBuilder.UseCors(new Microsoft.Owin.Cors.CorsOptions() { });
            ConfigureOAuth(appBuilder);
            
            WebApiConfig.Register(httpConfiguration);
        }

        private void ConfigureOAuth(IAppBuilder appBuilder)
        {
            OAuthAuthorizationServerOptions oAuthAuthorizationServerOptions = new OAuthAuthorizationServerOptions()
            {
                TokenEndpointPath = new Microsoft.Owin.PathString("/token"), // token path belirtiyoruz
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(3),
                AllowInsecureHttp = true,
                Provider = new SimpleAuthorizationServerProvider(),
                RefreshTokenProvider=new ApplicationRefreshTokenProvider(),
                AuthorizeEndpointPath = new PathString("/api/Account/ExternalLogin")
            };


            appBuilder.UseOAuthAuthorizationServer(oAuthAuthorizationServerOptions);
            appBuilder.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}
