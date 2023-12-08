using IdentityApp.Models;

namespace IdentityApp.ViewModels
{
    public class ClaimsVM
    {
        public ClaimsVM()
        {
            ClaimList = [];
        }

        public AppUser User { get; set; }
        public List<ClaimSelection> ClaimList { get; set; }
    }

    public class ClaimSelection
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}
