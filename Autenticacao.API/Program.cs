using Autenticacao.API.Configuration;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddApiConfiguration(builder.Configuration);

builder.Services.AddAuthConfiguration(builder.Configuration);


var app = builder.Build();

app.UseApiConfiguration();
