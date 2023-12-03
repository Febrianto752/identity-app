using IdentityApp.Models;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        [HttpGet]
        public IActionResult Register([FromQuery] string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterVM registerVM, [FromQuery] string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var user = new AppUser
                {
                    UserName = registerVM.Email,
                    Email = registerVM.Email,
                    Name = registerVM.Name,
                };

                var result = await _userManager.CreateAsync(user, registerVM.Password);

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnUrl);
                }

                if (result.Errors.Count() > 0)
                {
                    AddErrorsMessage(result);
                }
            }

            return View(registerVM);
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult Login([FromQuery] string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginVM loginVM, [FromQuery] string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(loginVM.Email, loginVM.Password, loginVM.RememberMe, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(loginVM);
                }
            }

            return View(loginVM);
        }

        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordVM forgotPasswordVM)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(forgotPasswordVM.Email);
                if (user == null)
                {
                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", new
                {
                    userId = user.Id,
                    code
                }, protocol: HttpContext.Request.Scheme);

                _emailSender?.SendEmailAsync(forgotPasswordVM.Email, "Reset Password", $"Please reset your password by clicking <a href='{callbackUrl}'>link</a> here");
            }
            return View(forgotPasswordVM);
        }

        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        private void AddErrorsMessage(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
