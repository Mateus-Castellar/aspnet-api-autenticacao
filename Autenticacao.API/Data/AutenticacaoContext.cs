using Autenticacao.API.Auth;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Autenticacao.API.Data;

public class AutenticacaoContext : IdentityDbContext<ApplicationUser>
{
    public AutenticacaoContext(DbContextOptions<AutenticacaoContext> context) : base(context) { }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}
