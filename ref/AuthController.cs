using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Caching.Memory;

using PPG.Core.Business;
using PPG.Core.Common;
using PPG.Core.Common.Entities;
using PPG.Core.Data;
using PPG.Core.Models;

using PetraLib.Core.Service;

namespace PPG.API.Controllers
{
    /// <summary>
    /// api/auth
    /// </summary>
    [AllowAnonymous]
    [ApiVersion("1.0")]
    [Route("api/[controller]")]
    public class authController : Controller
    {
        private readonly SecurityManager securityManager;
        private SymmetricSecurityKey JWTSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWTSecretKey")));

        /// <summary>
        /// Base constructor for the authController
        /// </summary>
        public authController(IHttpContextAccessor context, IMemoryCache memoryCache)
        {
            securityManager = new SecurityManager(new PPGContext());
        }

        /// <summary>
        /// Requests a JWT based on the provided username & password
        /// </summary>
        /// <param name="username">Username of the user requesting access</param>
        /// <param name="password">Password of the user requesting access</param>
        [HttpPost("token")]
        public async Task<IActionResult> Token(string username, string password)
        {
            // Obviously the username and password parameters have to be provided or 
            // there is nothing to validate.
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                
                OpResult<User> authenticatedUserResult = await securityManager.AuthenticateUserAsync(username, password);

                if (authenticatedUserResult.Code == OperationResultCode.Success)
                {
                    User authenticatedUser = authenticatedUserResult.Result;

                    ClaimsIdentity userClaimsIdentity = new ClaimsIdentity(new GenericIdentity(authenticatedUser.Id.ToString(), "Token"));
                    UserModel userModel = authenticatedUser.ToViewModel();
                    userClaimsIdentity.AddClaims(userModel.ToClaims());
                    LoadClientIdForClients(userModel, authenticatedUser);

                    return GenerateToken(userClaimsIdentity);
                }
            }

            return BadRequest("Username & password must be provided & valid.");
        }

        /// <summary>
        /// Requests a new JWT security token based off the provided refresh token
        /// </summary>
        [HttpPost("refresh/{refreshToken}")]
        public async Task<IActionResult> Refresh(string refreshToken)
        {
            // Obviously the refreshToken has to be provided or 
            // there is nothing to validate.
            if (!string.IsNullOrEmpty(refreshToken))
            {
                refreshToken = refreshToken.Replace("Bearer", "");
                refreshToken = refreshToken.Replace("bearer", "");

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    OpResult<User> authenticatedUserResult = await securityManager.AuthenticateRefreshTokenAsync(refreshToken);

                    if (authenticatedUserResult.Code == OperationResultCode.Success)
                    {
                        User authenticatedUser = authenticatedUserResult.Result;

                        ClaimsIdentity userClaimsIdentity = new ClaimsIdentity(new GenericIdentity(authenticatedUser.Id.ToString(), "Token"));
                        UserModel userModel = authenticatedUser.ToViewModel();
                        userClaimsIdentity.AddClaims(userModel.ToClaims());
                        LoadClientIdForClients(userModel, authenticatedUser);

                        return GenerateToken(userClaimsIdentity, true);
                    }
                }
            }

            // Credentials are invalid, or account doesn't exist
            return BadRequest("Refresh token must be provided & valid.");
        }

        private IActionResult GenerateToken(ClaimsIdentity identity, bool isRefresh = false)
        {
            string newRefreshToken = "";

            var now = DateTime.UtcNow;

            // Create claims array that will hold all the identity claims plus these 3 standard claims
            var claims = new Claim[identity.Claims.Count() + 3];

            // Add these standard claims
            claims[0] = new Claim(JwtRegisteredClaimNames.Sub, identity.Name);
            claims[1] = new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString());
            claims[2] = new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(now).ToString(), ClaimValueTypes.Integer64);

            if (identity.Claims.FirstOrDefault(f => f.Type.Equals("refreshToken")) != null)
            {
                newRefreshToken = identity.Claims.FirstOrDefault(f => f.Type.Equals("refreshToken")).Value;
            }

            // Add the identity claims
            identity.Claims.Where(f => !f.Type.Equals("refreshToken")).ToArray<Claim>().CopyTo(claims, 3);

            var token = new JwtSecurityToken(
                                        "PPG",
                                        "PPGAud",
                                        claims,
                                        expires: now.AddHours(1),
                                        signingCredentials: new SigningCredentials(JWTSigningKey, SecurityAlgorithms.HmacSha256));
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(token);

            if (!isRefresh)
            {
                var response = new
                {
                    access_token = encodedJwt,
                    expires_in = 3600,
                    refresh_token = newRefreshToken
                };

                // Serialize and return the response
                return Json(response);
            }
            else
            {
                var response = new
                {
                    access_token = encodedJwt,
                    expires_in = 3600
                };

                // Serialize and return the response
                return Json(response);
            }
        }

        private static long ToUnixEpochDate(DateTime date)
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

        /// <summary>
        /// Loads the ClientId property of the UserModel if the UserType is Contact
        /// </summary>
        /// <param name="userModel">UserModel to set ClientId on</param>
        /// <param name="user">User to retrieve client from</param>
        private void LoadClientIdForClients(UserModel userModel, User user)
        {
            if (userModel.UserTypeId == (int)Constants.Enums.UserType.Contact &&
                user.Clients.Count > 0)
            {
                int clientId = user.Clients.FirstOrDefault().Id;
                userModel.ClientId = clientId;
            }
        }
    }
}
