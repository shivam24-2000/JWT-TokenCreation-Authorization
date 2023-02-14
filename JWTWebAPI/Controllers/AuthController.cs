﻿using JWTWebAPI.Services.UserService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration= configuration;
            _userService = userService;
        }

        [HttpGet,Authorize ]

        public ActionResult<string> GetMe()
        {
            var userName = _userService.GetMyName();

            return Ok(userName);
            /*var userName = User?.Identity?.Name;
            var userName2 = User.FindFirstValue(ClaimTypes.Name);
            var userRole = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new {userName, userName2, userRole});*/
        }

        [HttpPost("register")]

        public async Task<ActionResult<User>> Register(UserDto request)
        {

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username= request.Username;
            user.PasswordHash= passwordHash;
            user.PasswordSalt= passwordSalt;

            return Ok(user);


        }

        [HttpPost("login")]

        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if( user.Username != request.Username )
            {
                return BadRequest("Username not Found!");
            }

            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt)) 
            {
                return BadRequest("Wrong Password");
            }
            string token = CreateToken(user);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpPost("refresh-token")]

        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if(!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token");
            }
            else if(user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token Expired");
            }
            string token = CreateToken(user);
            var newrefreshToken = GenerateRefreshToken();
            SetRefreshToken(newrefreshToken);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created= DateTime.Now
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOption = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires,
            };

            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOption);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials : creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

       
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }

        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt)) 
            {
                var ComputeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes((string)password));
                return ComputeHash.SequenceEqual( passwordHash);
            }
        }
    }
}
