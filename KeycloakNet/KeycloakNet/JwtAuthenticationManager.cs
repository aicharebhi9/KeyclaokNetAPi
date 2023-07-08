﻿using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace KeycloakNet
{
    public class JwtAuthenticationManager
    {
            //key declaration
            private readonly string key;

            private readonly IDictionary<string, string> users = new Dictionary<string, string>()
             { {"test", "password"}, {"test1", "password1"}, {"user", "password"} };

            public JwtAuthenticationManager(string key)
            {
                this.key = key;
            }

            public string Authenticate(string username, string password)
            {
                //auth failed - creds incorrect
                if (!users.Any(u => u.Key == username && u.Value == password))
                {
                    return null;
                }
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                var tokenKey = Encoding.ASCII.GetBytes(key);


                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.Name, username)
                    }),
                   
                    //set duration of token here
                    Expires = DateTime.UtcNow.AddHours(2),

                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(tokenKey),
                        SecurityAlgorithms.HmacSha256Signature) //setting sha256 algorithm
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);

                return tokenHandler.WriteToken(token);
            }
        }
    }

