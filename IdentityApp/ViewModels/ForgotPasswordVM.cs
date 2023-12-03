using System.ComponentModel.DataAnnotations;

namespace IdentityApp.ViewModels
{
    public class ForgotPasswordVM
    {
        [Required, EmailAddress]
        public string Email { get; set; }

    }
}
