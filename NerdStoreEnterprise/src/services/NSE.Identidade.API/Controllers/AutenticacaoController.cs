using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NSE.Identidade.API.Models;

namespace NSE.Identidade.API.Controllers;

[ApiController]
[Route("api/identidade")]
public class AutenticacaoController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AutenticacaoController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpPost("nova-conta")]
    public async Task<ActionResult> Registrar(RegistroViewModel registroViewModel)
    {
        if (!ModelState.IsValid) return BadRequest();

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
            await _signInManager.SignInAsync(usuario, false);
            return Ok();
        }

        return BadRequest();
    }

    [HttpPost("autenticar")]
    public async Task<ActionResult> Login(LoginViewModel loginViewModel)
    {
        if (!ModelState.IsValid) return BadRequest();

        // lockoutOnFailure: Define se o usuário será bloqueado após várias tentativas de login
        var usuarioAutenticado = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Senha, false, true);

        if (usuarioAutenticado.Succeeded)
        {
            return Ok();
        }

        return BadRequest();
    }
}