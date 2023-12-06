using System.ComponentModel.DataAnnotations;

namespace IdentityApp.ViewModels
{
    public class LoginWithOtpVM
    {
        [Required]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }
        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
