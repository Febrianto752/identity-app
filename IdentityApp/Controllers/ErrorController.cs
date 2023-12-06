using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class ErrorController : Controller
    {
        [ActionName("NotFound")]
        public IActionResult NotFoundPage()
        {
            return View("NotFound");
        }

        [ActionName("Unauthorize")]
        public IActionResult UnauthorizedPage()
        {
            return View("Unauthorize");
        }

        [ActionName("Forbidden")]
        public IActionResult ForbiddenPage()
        {
            return View("Forbidden");
        }

        [ActionName("BadRequest")]
        public IActionResult BadRequestPage()
        {
            return View("BadRequest");
        }
    }
}
