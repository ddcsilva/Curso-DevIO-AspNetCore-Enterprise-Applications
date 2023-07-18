using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NSE.Identidade.API.Data;
using NSE.Identidade.API.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddDefaultIdentity<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

var appSettingsSection = builder.Configuration.GetSection("AppSettings");
builder.Services.Configure<AppSettings>(appSettingsSection);

var appSettings = appSettingsSection.Get<AppSettings>();
var key = Encoding.ASCII.GetBytes(appSettings.Secret);

builder.Services.AddAuthentication(options =>
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

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "NerdStore Enterprise Identity API",
        Description = "Esta API faz parte do curso ASP.NET Core Enterprise Applications.",
        Contact = new OpenApiContact() { Name = "Danilo Silva", Email = "danilo.silva@msn.com" },
        License = new OpenApiLicense() { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
