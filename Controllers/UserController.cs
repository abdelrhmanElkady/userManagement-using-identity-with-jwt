using dotnetClaimAuthorization.BindingModel;
using dotnetClaimAuthorization.Data.Entities;
using dotnetClaimAuthorization.DTO;
using dotnetClaimAuthorization.Enums;
using dotnetClaimAuthorization.Models;
using dotnetClaimAuthorization.Models.BindingModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace dotnetClaimAuthorization.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        

       

        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTConfig _JWTConfig;

        public UserController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager ,IOptions<JWTConfig> jwtConfig, RoleManager<IdentityRole> roleManager)
        {
           
            _userManager = userManager;
            _signInManager = signInManager;
            _JWTConfig = jwtConfig.Value;
            _roleManager = roleManager;
        }

        [HttpPost("RegisterUser")]
        public async Task<object> RegisterUser([FromBody] AddUpdateRegisterUserBindingModel model)
        {
            try
            {
                if(model.Roles == null)
                {
                    return await Task.FromResult(new ResponseModel(Responsecode.Error, "roles are missing", null));
                }
                foreach(var role in model.Roles)
                {
                    if (!await _roleManager.RoleExistsAsync(role))
                    {
                        return await Task.FromResult(new ResponseModel(Responsecode.Error, "role does not exist", null));
                    }
                }
                

                // checking if the user email already existed
                if(await _userManager.FindByEmailAsync(model.Email) is not null)
                {
                    return await Task.FromResult(new ResponseModel(Responsecode.Error, "email already existed", null));
                }

                // checking if the user name already existed
                if (await _userManager.FindByEmailAsync(model.FullName) is not null)
                {
                  
                    return await Task.FromResult(new ResponseModel(Responsecode.Error, "user name  already existed", null));

                }
                var user = new AppUser()
                {
                    FullName = model.FullName,
                    Email = model.Email,
                    DateCreated = DateTime.UtcNow,
                    DateModified = DateTime.UtcNow,
                    UserName = model.Email
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var tempUser = await _userManager.FindByEmailAsync(model.Email);
                    foreach (var role in model.Roles)
                    {
                        await _userManager.AddToRoleAsync(tempUser, role);
                    }
                        

                    return await Task.FromResult(new ResponseModel(Responsecode.Ok ,"user has been regiestered", null));
                }
     
                return await Task.FromResult(new ResponseModel(Responsecode.Error, "", string.Join(",", result.Errors.Select(x => x.Description).ToArray())));
            }
            catch (Exception ex)
            {
               
                return await Task.FromResult(new ResponseModel(Responsecode.Error, ex.Message, null));
            }
            
        }

        //[Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme)]
        [Authorize]
        [HttpGet("GetAllUsers")]
        public async Task<object> GetAllUsers()
        {
            try
            {
                List<userDTO> allUserDTO = new List<userDTO>();
                var users = _userManager.Users.ToList();
                foreach (var user in users)
                {
                    var roles = (await _userManager.GetRolesAsync(user)).ToList();
                  allUserDTO.Add(new userDTO(user.FullName, user.Email, user.DateCreated, user.DateModified, roles));
                }

                
                return await Task.FromResult(new ResponseModel(Responsecode.Ok, "", allUserDTO));
            }
            catch (Exception ex)
            {
            
                return await Task.FromResult(new ResponseModel(Responsecode.Error, ex.Message, null));
            }
        }

        [Authorize(Roles ="admin")]
        [HttpGet("GetAdmins")]
        public async Task<object> GetAdmins()
        {
            try
            {
                List<userDTO> allUserDTO = new List<userDTO>();
                var users = _userManager.Users.ToList();
                foreach (var user in users)
                {
                    var roles = (await _userManager.GetRolesAsync(user)).ToList();
                    if(roles.Any(role=>role == "admin"))
                    {
                        allUserDTO.Add(new userDTO(user.FullName, user.Email, user.DateCreated, user.DateModified, roles));

                    }
                }


                return await Task.FromResult(new ResponseModel(Responsecode.Ok, "", allUserDTO));
            }
            catch (Exception ex)
            {

                return await Task.FromResult(new ResponseModel(Responsecode.Error, ex.Message, null));
            }
        }

        [HttpPost("login")]
        public async Task<object> Login([FromBody] LoginBindingModel model)
        {
            try
            {
                if(model.Email == "" || model.Password == "")
                {
               
                    return await Task.FromResult(new ResponseModel(Responsecode.Error, "email or password is missing", null));
                }

                var result = await _signInManager.PasswordSignInAsync(model.Email,model.Password,false,false);

                if (result.Succeeded)
                {
                    var appUser = await _userManager.FindByEmailAsync(model.Email);
                    var roles = (await _userManager.GetRolesAsync(appUser)).ToList();
                    var user = new userDTO(appUser.FullName, appUser.Email, appUser.DateCreated, appUser.DateModified,roles);
                    user.Token = GenerateToken(appUser,roles);

         
                    return await Task.FromResult(new ResponseModel(Responsecode.Ok, "", user));
                }
               
                return await Task.FromResult(new ResponseModel(Responsecode.Error, "invalid email or password", null));
            }
            catch (Exception ex)
            {
              
                return await Task.FromResult(new ResponseModel(Responsecode.Error, ex.Message, null));
            }
        }

        private string GenerateToken(AppUser user,List<string> roles)
        {
            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                   
            };
            foreach(var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_JWTConfig.Key);
            var tokenDescription = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(12),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _JWTConfig.Audience,
                Issuer = _JWTConfig.Issure

                
            };
            var token = jwtTokenHandler.CreateToken(tokenDescription);
            return jwtTokenHandler.WriteToken(token);
            
        }

        [Authorize]
        [HttpPost("addRole")]
        public async Task<object> AddRole([FromBody] addRoleBindingModel model)
        {
            try
            {
                if(model == null && model.Role =="")
                {
                    return await Task.FromResult(new ResponseModel(Responsecode.Error, "parameter is missing", null));
                }
                if(await _roleManager.RoleExistsAsync(model.Role))
                {
                    return await Task.FromResult(new ResponseModel(Responsecode.Error, "role already exist", null));
                }

                var role = new IdentityRole();
                role.Name = model.Role;
                var result = await _roleManager.CreateAsync(role);
                if (result.Succeeded)
                {
                    return await Task.FromResult(new ResponseModel(Responsecode.Ok, "role added successfully", null));
                }

                return await Task.FromResult(new ResponseModel(Responsecode.Error, "something went wrong", null));
            }
            catch (Exception ex)
            {
                return await Task.FromResult(new ResponseModel(Responsecode.Error, ex.Message, null));
            }
        }

        [HttpGet("GetRoles")]
        public async Task<object> GetRoles()
        {
            try
            {
                var roles = _roleManager.Roles.Select(x => x.Name).ToList();
                return await Task.FromResult(new ResponseModel(Responsecode.Ok, "", roles));
            }catch (Exception ex)
            {
                return await Task.FromResult(new ResponseModel(Responsecode.Error, ex.Message, null));
            }
           
        }

    }
}