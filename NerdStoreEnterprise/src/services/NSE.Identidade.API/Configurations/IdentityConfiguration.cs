using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NSE.Identidade.API.Data;
using NSE.Identidade.API.Extensions;

namespace NSE.Identidade.API.Configurations;

public static class IdentityConfiguration
{
    public static IServiceCollection AddIdentityConfiguration(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddDefaultIdentity<IdentityUser>()
            .AddRoles<IdentityRole>()
            .AddErrorDescriber<IdentityMensagensPortugues>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // Configuração do JWT
        var appSettingsSection = configuration.GetSection("AppSettings");
        services.Configure<AppSettings>(appSettingsSection);

        var appSettings = appSettingsSection.Get<AppSettings>();
        var key = Encoding.ASCII.GetBytes(appSettings.Secret);

        services.AddAuthentication(options =>
        {
            // DefaultAuthenticateScheme: Define o esquema padrão para autenticação.
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            // DefaultChallengeScheme: Define o esquema padrão para desafio de autenticação.
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(bearerOptions =>
        {
            // RequireHttpsMetadata: Define se o HTTPS é obrigatório ou não.
            bearerOptions.RequireHttpsMetadata = true;
            // SaveToken: Define se o token deve ser gravado no contexto HTTP.
            bearerOptions.SaveToken = true;
            // TokenValidationParameters: Define os parâmetros de validação do token.
            bearerOptions.TokenValidationParameters = new TokenValidationParameters
            {
                // ValidateIssuerSigningKey: Define se a chave de assinatura deve ser validada.
                ValidateIssuerSigningKey = true,
                // IssuerSigningKey: Define a chave de assinatura.
                IssuerSigningKey = new SymmetricSecurityKey(key),
                // ValidateIssuer: Define se o emissor deve ser validado.
                ValidateIssuer = true,
                // ValidateAudience: Define se o público deve ser validado.
                ValidAudience = appSettings.ValidoEm,
                // ValidateIssuer: Define se o emissor deve ser validado.
                ValidIssuer = appSettings.Emissor,
            };
        });

        return services;
    }

    public static IApplicationBuilder UseIdentityConfiguration(this IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }
}