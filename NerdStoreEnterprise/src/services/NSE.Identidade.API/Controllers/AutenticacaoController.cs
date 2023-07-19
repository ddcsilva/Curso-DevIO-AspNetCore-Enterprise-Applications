using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSE.Identidade.API.Extensions;
using NSE.Identidade.API.Models;

namespace NSE.Identidade.API.Controllers;

[Route("api/identidade")]
public class AutenticacaoController : MainController
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly AppSettings _appSettings;

    // IOptions: Interface que permite acessar as configurações da aplicação
    public AutenticacaoController(SignInManager<IdentityUser> signInManager,
                                  UserManager<IdentityUser> userManager,
                                  IOptions<AppSettings> appSettings)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _appSettings = appSettings.Value;
    }

    [HttpPost("nova-conta")]
    public async Task<ActionResult> Registrar(RegistroViewModel registroViewModel)
    {
        if (!ModelState.IsValid) return CustomResponse(ModelState);

        var usuario = new IdentityUser
        {
            UserName = registroViewModel.Email,
            Email = registroViewModel.Email,
            EmailConfirmed = true
        };

        var usuarioCriado = await _userManager.CreateAsync(usuario, registroViewModel.Senha);

        if (usuarioCriado.Succeeded)
        {
            // isPersistent: Define se o cookie de autenticação será persistente ou não 
            return CustomResponse(await GerarJwt(registroViewModel.Email));
        }

        foreach (var erro in usuarioCriado.Errors)
        {
            AdicionarErroProcessamento(erro.Description);
        }

        return CustomResponse();
    }

    [HttpPost("autenticar")]
    public async Task<ActionResult> Login(LoginViewModel loginViewModel)
    {
        if (!ModelState.IsValid) return CustomResponse(ModelState);

        // lockoutOnFailure: Define se o usuário será bloqueado após várias tentativas de login
        var usuarioAutenticado = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Senha, false, true);

        if (usuarioAutenticado.Succeeded)
        {
            return CustomResponse(await GerarJwt(loginViewModel.Email));
        }

        if (usuarioAutenticado.IsLockedOut)
        {
            AdicionarErroProcessamento("Usuário temporariamente bloqueado por tentativas inválidas");
            return CustomResponse();
        }

        AdicionarErroProcessamento("Usuário ou senha incorretos");
        return CustomResponse();
    }

    private async Task<LoginResponseViewModel> GerarJwt(string email)
    {
        var usuario = await _userManager.FindByEmailAsync(email);
        var claims = await _userManager.GetClaimsAsync(usuario);

        var identityClaims = await ObterClaimsUsuario(claims, usuario);
        var encodedToken = CodificarToken(identityClaims);

        return ObterRespostaToken(encodedToken, usuario, claims);
    }

    private async Task<ClaimsIdentity> ObterClaimsUsuario(ICollection<Claim> claims, IdentityUser usuario)
    {
        var papeisUsuario = await _userManager.GetRolesAsync(usuario);

        // Sub: Define o subject do token, ou seja, quem está recebendo o token
        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, usuario.Id));
        // Email: Define o email do usuário que está recebendo o token
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, usuario.Email));
        // Jti: Define um id para o token
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        // Nbf: Define a data de início de validade do token
        claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
        // Iat: Define a data de expiração do token
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

        foreach (var papel in papeisUsuario)
        {
            claims.Add(new Claim("role", papel));
        }

        var identityClaims = new ClaimsIdentity();
        identityClaims.AddClaims(claims);

        return identityClaims;
    }

    private string CodificarToken(ClaimsIdentity identityClaims)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _appSettings.Emissor,
            Audience = _appSettings.ValidoEm,
            Subject = identityClaims,
            Expires = DateTime.UtcNow.AddHours(_appSettings.ExpiracaoHoras),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        });

        return tokenHandler.WriteToken(token);
    }

    private LoginResponseViewModel ObterRespostaToken(string encodedToken, IdentityUser usuario, IEnumerable<Claim> claims)
    {
        return new LoginResponseViewModel
        {
            TokenDeAcesso = encodedToken,
            ExpiracaoToken = TimeSpan.FromHours(_appSettings.ExpiracaoHoras).TotalSeconds,
            UsuarioToken = new UsuarioTokenViewModel
            {
                Id = usuario.Id,
                Email = usuario.Email,
                Claims = claims.Select(c => new UsuarioClaimViewModel { Tipo = c.Type, Valor = c.Value })
            }
        };
    }

    private static long ToUnixEpochDate(DateTime date)
    {
        // Retorna a data em segundos desde 01/01/1970
        return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}