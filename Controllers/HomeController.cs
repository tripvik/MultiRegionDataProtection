using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MultiRegionDataProtection.Models;
using System.Diagnostics;
using System.Text.Json;

namespace MultiRegionDataProtection.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IDataProtectionProvider _dataProtector;
        public HomeController(ILogger<HomeController> logger, IDataProtectionProvider dataProtector)
        {
            _logger = logger;
            _dataProtector = dataProtector;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [HttpPost]
        public IActionResult DecryptCookie(string cookieValue)
        {
            if (string.IsNullOrEmpty(cookieValue))
            {
                ViewBag.DecryptedData = "Cookie value is empty.";
                return View("Index");
            }
            try
            {
                var protector = _dataProtector.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2");
                var ticketDataFormat = new TicketDataFormat(protector);
                var ticket = ticketDataFormat.Unprotect(cookieValue, "");
                var cookieProperties = JsonSerializer.Serialize(ticket!.Properties, new JsonSerializerOptions { WriteIndented = true });
                ViewBag.DecryptedData = cookieProperties;
            }
            catch (Exception ex)
            {
                ViewBag.DecryptedData = "Decryption Failed";
            }
            return View("Index");
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
