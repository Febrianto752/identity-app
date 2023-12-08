using IdentityApp.Data;
using IdentityApp.Models;
using IdentityApp.Utilities;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class UserController : Controller
    {
        private readonly AppDbContext _db;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(AppDbContext db, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var userList = _db.AppUsers.ToList();
            var userRoles = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach (var user in userList)
            {
                var role = userRoles.FirstOrDefault(u => u.UserId == user.Id);
                if (role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
                }
            }

            return View(userList);
        }

        [HttpGet]
        public async Task<IActionResult> ManageRole(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var existingUserRoles = await _userManager.GetRolesAsync(user);
            var model = new RolesVM()
            {
                User = user
            };

            foreach (var role in _roleManager.Roles)
            {
                var roleSelection = new RoleSelection
                {
                    RoleName = role.Name
                };

                if (existingUserRoles.Any(roleName => roleName == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RoleList.Add(roleSelection);
            }

            return View(model);
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesVM rolesVM)
        {
            var user = await _userManager.FindByIdAsync(rolesVM.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldUserRoles = await _userManager.GetRolesAsync(user);
            var removingOldRoles = await _userManager.RemoveFromRolesAsync(user, oldUserRoles);

            if (!removingOldRoles.Succeeded)
            {
                TempData[Status.Error] = "Error while removing roles";
                return View(rolesVM);
            }

            var addRolesToUser = await _userManager.AddToRolesAsync(user, rolesVM.RoleList.Where(role => role.IsSelected).Select(role => role.RoleName));


            if (!addRolesToUser.Succeeded)
            {
                TempData[Status.Error] = "Error while adding roles";
                return View(rolesVM);
            }

            TempData[Status.Success] = "Roles assigned successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}
