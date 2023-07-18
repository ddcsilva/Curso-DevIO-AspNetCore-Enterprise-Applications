namespace NSE.Identidade.API.Models;

public class LoginResponseViewModel
{
    public string TokenDeAcesso { get; set; }
    public double ExpiracaoToken { get; set; }
    public UsuarioTokenViewModel UsuarioToken { get; set; }
}