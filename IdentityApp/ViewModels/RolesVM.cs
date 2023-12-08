using IdentityApp.Models;

namespace IdentityApp.ViewModels
{
	public class RolesVM
	{
		public RolesVM()
		{
			RoleList = [];
		}

		public AppUser User { get; set; }
		public List<RoleSelection> RoleList { get; set; }
	}

	public class RoleSelection
	{
		public string RoleName { get; set; }
		public bool IsSelected { get; set; }
	}
}
