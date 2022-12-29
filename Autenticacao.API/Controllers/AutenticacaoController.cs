using Autenticacao.API.Auth;
using Autenticacao.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Autenticacao.API.Controllers;

[Route("api/autenticacao")]
public class AutenticacaoController : CoreController
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public AutenticacaoController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login(LoginModel login)
    {
        if (string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password)) return BadRequest(ModelState);

        var user = await _userManager.FindByNameAsync(login.Username);

        if (user is not null && await _userManager.CheckPasswordAsync(user, login.Password))
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles) authClaims.Add(new Claim(ClaimTypes.Role, userRole));

            var token = CreateToken(authClaims);
            var refreshToken = GenerateRefreshToken();

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                Expiration = token.ValidTo
            });
        }

        return Unauthorized();
    }

    [HttpPost]
    [Route("cadastrar")]
    public async Task<IActionResult> Cadastro(CadastroModel cadastro)
    {
        if (string.IsNullOrEmpty(cadastro.Username) || string.IsNullOrEmpty(cadastro.Email) ||
            string.IsNullOrEmpty(cadastro.Password)) return BadRequest(ModelState);

        var usuarioExiste = await _userManager.FindByNameAsync(cadastro.Username);

        if (usuarioExiste is not null)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new AuthResponseModel
            {
                Status = "error",
                Message = "o usuario ou email já estão sendo utilizados"
            });
        }

        ApplicationUser user = new()
        {
            Email = cadastro.Email,
            UserName = cadastro.Username,
            SecurityStamp = Guid.NewGuid().ToString(),
        };

        var result = await _userManager.CreateAsync(user, cadastro.Password);

        if (result.Succeeded is false)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new AuthResponseModel
            {
                Status = "error",
                Message = "falha ao cadastrar usuário, verfique seus dados de entrada"
            });
        }

        return Ok(new AuthResponseModel { Status = "success", Message = "usuário cadastrado com sucesso!" });
    }

    [HttpPost]
    [Route("cadastrar-admin")]
    public async Task<IActionResult> RegisterAdmin([FromBody] CadastroModel cadastro)
    {
        if (string.IsNullOrEmpty(cadastro.Username) || string.IsNullOrEmpty(cadastro.Email) ||
           string.IsNullOrEmpty(cadastro.Password)) return BadRequest(ModelState);

        var userExists = await _userManager.FindByNameAsync(cadastro.Username);

        if (userExists is not null)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new AuthResponseModel
            {
                Status = "Error",
                Message = "Usuário já existe!"
            });
        }

        ApplicationUser user = new()
        {
            Email = cadastro.Email,
            UserName = cadastro.Username,
            SecurityStamp = Guid.NewGuid().ToString(),
        };

        var result = await _userManager.CreateAsync(user, cadastro.Password);

        if (result.Succeeded is false)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new AuthResponseModel
            {
                Status = "Error",
                Message = "User creation failed! Please check user details and try again."
            });
        }

        if (await _roleManager.RoleExistsAsync(UserRoles.Admin) is false) await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
        if (await _roleManager.RoleExistsAsync(UserRoles.User) is false) await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

        if (await _roleManager.RoleExistsAsync(UserRoles.Admin)) await _userManager.AddToRoleAsync(user, UserRoles.Admin);
        if (await _roleManager.RoleExistsAsync(UserRoles.Admin)) await _userManager.AddToRoleAsync(user, UserRoles.User);

        return Ok(new AuthResponseModel
        {
            Status = "Success",
            Message = "usuário cadastrado com sucesso!"
        });
    }

    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
    {
        if (tokenModel is null) return BadRequest("Invalid client request");

        string? accessToken = tokenModel.AccessToken;
        string? refreshToken = tokenModel.RefreshToken;

        var principal = GetPrincipalFromExpiredToken(accessToken);

        if (principal is null) return BadRequest("Invalid access token or refresh token");

        string? username = principal.Identity?.Name;

        var user = await _userManager.FindByNameAsync(username ?? throw new ArgumentException(nameof(username)));

        if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var newAccessToken = CreateToken(principal.Claims.ToList());
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        await _userManager.UpdateAsync(user);

        return new ObjectResult(new
        {
            accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
            refreshToken = newRefreshToken
        });
    }

    [Authorize]
    [HttpPost]
    [Route("revoke/{username}")]
    public async Task<IActionResult> Revoke(string username)
    {
        var user = await _userManager.FindByNameAsync(username);

        if (user is null) return BadRequest("Username inválido!");

        user.RefreshToken = null;
        await _userManager.UpdateAsync(user);

        return NoContent();
    }

    [Authorize]
    [HttpPost]
    [Route("revoke-all")]
    public async Task<IActionResult> RevokeAll()
    {
        var users = _userManager.Users.ToList();

        foreach (var user in users)
        {
            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
        }

        return NoContent();
    }

    #region Metodos Auxialiares

    private JwtSecurityToken CreateToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"] ?? throw new ArgumentException("JWT:Secret")));

        _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:sValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

        return token;
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"] ?? throw new ArgumentException("JWT:Secret"))),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase) is false)
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

    #endregion
}
