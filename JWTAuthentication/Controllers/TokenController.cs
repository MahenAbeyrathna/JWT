using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Controllers
{
    //[Produces("application/json")]
    //[Route("api/Token")]
    public class TokenController : Controller
    {
        private const string securityKey = "this is my custom Secret key for authnetication";
        public static readonly SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TokenController.securityKey));

        [Authorize(Roles = "docker-users")]
        [HttpGet]
        [Route("api/token/{user}/{password}")]
        public IActionResult GetToken(string user, string password)
        {
            if(! string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(password))
            {
                return Ok(GenerateToken(user, password));
            }
            else
            {
                return BadRequest();
            }
            
        }

        private string GenerateToken(string user, string password)
        {
            var token = new JwtSecurityToken(
                claims: new Claim[]
                {
                    new Claim(ClaimTypes.Name,user)
                },
                notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                expires: new DateTimeOffset(DateTime.Now.AddMinutes(2)).DateTime,
                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}