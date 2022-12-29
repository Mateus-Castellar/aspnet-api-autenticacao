using Autenticacao.API.Data;
using Microsoft.EntityFrameworkCore;

namespace Autenticacao.API.Configuration;

public static class ApiConfiguration
{
    public static void AddApiConfiguration(this IServiceCollection services, ConfigurationManager configuration)
    {
        services.AddDbContext<AutenticacaoContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddControllers();

        services.AddEndpointsApiExplorer();

        services.AddSwaggerGen();
    }


    public static void UseApiConfiguration(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}
