using Microsoft.AspNetCore.Authentication.Cookies;

namespace NSE.WebApp.MVC.Configurations;

public static class IdentityConfiguration
{
    // Adiciona o suporte a cookies na aplicação. Quando tiver um usuário autenticado, o cookie será criado e armazenado no navegador
    public static void AddIdentityConfiguration(this IServiceCollection services)
    {
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                // Quando o usuário não está autenticado, ele é redirecionado para a página de login
                options.LoginPath = "/login";
                // Quando o usuário não tem permissão para acessar uma determinada funcionalidade, ele é redirecionado para a página de acesso negado
                options.AccessDeniedPath = "/acesso-negado";
            });
    }

    public static void UseIdentityConfiguration(this IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
    }
}