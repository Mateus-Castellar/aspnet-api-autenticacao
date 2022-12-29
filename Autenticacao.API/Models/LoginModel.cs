using System.ComponentModel.DataAnnotations;

namespace Autenticacao.API.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "O campo nome é obrigatório")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "O campo senha é obrigatório")]
        public string? Password { get; set; }
    }
}
