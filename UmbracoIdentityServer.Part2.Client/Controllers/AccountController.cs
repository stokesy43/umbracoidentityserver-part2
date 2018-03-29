using IdentityModel;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using Umbraco.Core;
using Umbraco.Web;
using Umbraco.Web.Mvc;

namespace UmbracoIdentityServer.Part2.Client.Controllers
{
    public class AccountController : SurfaceController
    {

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            if (provider.IsNullOrWhiteSpace() && returnUrl.IsNullOrWhiteSpace())
            {
                return Redirect("/account");
            }

            if (returnUrl.IsNullOrWhiteSpace())
            {
                returnUrl = Request.RawUrl;
            }

            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.SurfaceAction<AccountController>("ExternalLoginCallback", new { ReturnUrl = returnUrl })
            }, provider);

            return new HttpUnauthorizedResult();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            // First get the authentication information from identity server
            var loginInfo = await HttpContext.GetOwinContext().Authentication.GetExternalLoginInfoAsync();

            if (loginInfo == null)
            {
                //go home, invalid callback
                return RedirectToLocal(returnUrl);
            }

            // Get the relevant claims from the external identity
            var email = loginInfo.ExternalIdentity.Claims.First(c => c.Type == JwtClaimTypes.Email).Value;
            var name = loginInfo.ExternalIdentity.Claims.First(c => c.Type == JwtClaimTypes.Name).Value;

            HttpContext.GetOwinContext().Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            var memberService = Services.MemberService;

            if (memberService.GetByEmail(email) == null)
            {
                var member = memberService.CreateMemberWithIdentity(email, email, name, "member");

                memberService.Save(member);

                memberService.AssignRole(member.Id, "Standard User");
            }

            FormsAuthentication.SetAuthCookie(email, false);

            return RedirectToLocal(returnUrl);

        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return Redirect("/");
        }

    }

}
