using Microsoft.AspNetCore.Identity;

namespace Autenticacao.API.Auth;

//extendendo os campos do identityUser
public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}
