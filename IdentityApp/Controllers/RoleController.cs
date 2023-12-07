using IdentityApp.Data;
using IdentityApp.Models;
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
                    TempData["Error"] = "Role already exists.";
                    return RedirectToAction(nameof(Index));
                }

                await _roleManager.CreateAsync(new IdentityRole() { Name = model.Name });
                TempData["Success"] = "Role created successfully";

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
                TempData["Error"] = "Role not found.";
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
                    TempData["Error"] = "Role not found.";
                    return RedirectToAction(nameof(Index));
                }

                if (model.Name != model.OldName)
                {
                    var roleIsExist = await _roleManager.RoleExistsAsync(model.Name);
                    if (roleIsExist)
                    {
                        TempData["Error"] = "Role already exists.";
                        return RedirectToAction(nameof(Index));
                    }

                }

                role.Name = model.Name;
                role.NormalizedName = model.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(role);
                TempData["Success"] = "Role updated successfully";

                return RedirectToAction(nameof(Index));
            }
            return View(model);
        }

    }
}
