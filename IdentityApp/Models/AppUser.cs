using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityApp.Models
{
    public class AppUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }
        [NotMapped]
        public string RoleId { get; set; }

        [NotMapped]
        public string Role { get; set; }
    }
}
