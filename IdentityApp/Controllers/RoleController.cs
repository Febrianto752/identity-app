using IdentityApp.Data;
using IdentityApp.Models;
using IdentityApp.Utilities;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class RoleController : Controller
    {
        private readonly AppDbContext _db;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(AppDbContext db, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _roleManager = roleManager;
            _userManager = userManager;
        }
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(IdentityRole model)
        {
            if (model.Name is null)
            {
                ModelState.AddModelError("Name", "Role Name is required!");
            }
            if (ModelState.IsValid)
            {
                if (await _roleManager.RoleExistsAsync(model.Name))
                {
                    //error
                    TempData[Status.Error] = "Role already exists.";
                    return RedirectToAction(nameof(Index));
                }

                await _roleManager.CreateAsync(new IdentityRole() { Name = model.Name });
                TempData[Status.Success] = "Role created successfully";

                return RedirectToAction(nameof(Index));
            }

            return View(model);
        }

        [HttpGet("Role/Edit/{id}")]
        public IActionResult Edit(string id)
        {
            var role = _db.Roles.FirstOrDefault(u => u.Id == id);
            if (role == null)
            {
                TempData[Status.Error] = "Role not found.";
                return RedirectToAction(nameof(Index));
            }

            var editRoleVM = new EditRoleVM { Name = role.Name, OldName = role.Name, RoleId = role.Id };
            return View(editRoleVM);
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditRoleVM model)
        {
            if (ModelState.IsValid)
            {
                var role = _db.Roles.FirstOrDefault(u => u.Id == model.RoleId);

                if (role == null)
                {
                    TempData[Status.Error] = "Role not found.";
                    return RedirectToAction(nameof(Index));
                }

                if (model.Name != model.OldName)
                {
                    var roleIsExist = await _roleManager.RoleExistsAsync(model.Name);
                    if (roleIsExist)
                    {
                        TempData[Status.Error] = "Role already exists.";
                        return RedirectToAction(nameof(Index));
                    }

                }

                role.Name = model.Name;
                role.NormalizedName = model.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(role);
                TempData[Status.Success] = "Role updated successfully";

                return RedirectToAction(nameof(Index));
            }
            return View(model);
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var role = _db.Roles.FirstOrDefault(u => u.Id == id);
            if (role == null)
            {
                TempData[Status.Error] = "Role not found.";
                return RedirectToAction(nameof(Index));
            }
            var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if (userRolesForThisRole > 0)
            {
                TempData[Status.Error] = "Cannot delete this role, since there are users assigned to this role.";
                return RedirectToAction(nameof(Index));
            }
            await _roleManager.DeleteAsync(role);
            TempData[Status.Success] = "Role deleted successfully.";
            return RedirectToAction(nameof(Index));
        }


    }
}
