using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CookieServiceProvider.Pages
{
    public class LogoutModel : PageModel
    {
        public async Task OnGetAsync(string? returnUrl = null)
        {
            var authenticationProperties = new AuthenticationProperties()
            {
                RedirectUri = returnUrl
            };

            // Logout the user locally.
            await HttpContext.SignOutAsync(authenticationProperties);
        }
    }
}
