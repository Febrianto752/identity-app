using IdentityApp.Data;
using IdentityApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class RolesController : Controller
    {
        private readonly AppDbContext _db;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(AppDbContext db, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
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
    }
}
