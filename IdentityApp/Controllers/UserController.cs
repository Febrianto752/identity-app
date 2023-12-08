using IdentityApp.Data;
using IdentityApp.Models;
using IdentityApp.Utilities;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

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

        public async Task<IActionResult> Index()
        {
            var userList = _db.AppUsers.ToList();
            //var userRoles = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach (var user in userList)
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                user.Role = String.Join(",", userRoles);
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


        [HttpPost, ValidateAntiForgeryToken]
        public IActionResult LockUnlock(string userId)
        {
            var user = _db.AppUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                //user is locked and will remain locked untill lockoutend time
                //clicking on this action will unlock them
                user.LockoutEnd = DateTime.Now;
                TempData[Status.Success] = "User unlocked successfully.";
            }
            else
            {
                //user is not locked, and we want to lock the user
                user.LockoutEnd = DateTime.Now.AddMonths(1);
                TempData[Status.Success] = "User locked successfully.";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));

        }

        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var user = _db.AppUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            _db.AppUsers.Remove(user);
            _db.SaveChanges();
            TempData[Status.Success] = "User deleted successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await _userManager.GetClaimsAsync(user);

            var model = new ClaimsVM()
            {
                User = user
            };

            foreach (Claim claim in ClaimStore.claimsList)
            {
                ClaimSelection userClaim = new ClaimSelection
                {
                    ClaimType = claim.Type
                };
                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.ClaimList.Add(userClaim);
            }

            return View(model);
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(ClaimsVM claimsVM)
        {
            var user = await _userManager.FindByIdAsync(claimsVM.User.Id);

            if (user == null)
            {
                return NotFound();
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claims);

            if (!result.Succeeded)
            {
                TempData[Status.Error] = "Error while removing claims";
                return View(claimsVM);
            }

            result = await _userManager.AddClaimsAsync(user,
                claimsVM.ClaimList.Where(c => c.IsSelected).Select(c => new Claim(c.ClaimType, c.IsSelected.ToString()))
                );

            if (!result.Succeeded)
            {
                TempData[Status.Error] = "Error while adding claims";
                return View(claimsVM);
            }

            TempData[Status.Success] = "Claims updated successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}
