using System.ComponentModel.DataAnnotations;

namespace Autenticacao.API.Models
{
    public class CadastroModel
    {
        [Required(ErrorMessage = "O campo nome é obrigatório")]
        public string? Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "O campo email é obrigatório")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "O campo senha é obrigatório")]
        public string? Password { get; set; }
    }
}
