using System.ComponentModel.DataAnnotations;

namespace IdentityApp.ViewModels
{
    public class EditRoleVM
    {
        [Required]
        public string RoleId { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string OldName { get; set; }
    }
}
