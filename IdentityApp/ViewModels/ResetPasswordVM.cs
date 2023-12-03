﻿using System.ComponentModel.DataAnnotations;

namespace IdentityApp.ViewModels
{
    public class ResetPasswordVM
    {
        public string Code { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required, StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6), DataType(DataType.Password)]
        public string Password { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "Confirm Password"), Compare("Password", ErrorMessage = "The password and confirm password do not match")]
        public string ConfirmPassword { get; set; }
    }
}
