using System.Security.Claims;
using Fluid;
using Fluid.Values;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using OrchardCore.Liquid;

namespace OrchardCore.Users.Liquid;

public class UserPhoneNumberFilter : ILiquidFilter
{
    private readonly UserManager<IUser> _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserPhoneNumberFilter(UserManager<IUser> userManager, IHttpContextAccessor httpContextAccessor)
    {
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
    }

    public async ValueTask<FluidValue> ProcessAsync(FluidValue input, FilterArguments args, LiquidTemplateContext ctx)
    {
        var value = input.ToObjectValue();
        if (value is LiquidUserAccessor)
        {
            var claimsPrincipal = _httpContextAccessor.HttpContext?.User;
            if (claimsPrincipal != null)
            {
                var phoneNumber = claimsPrincipal.FindFirstValue(ClaimTypes.MobilePhone);
                if (phoneNumber != null)
                {
                    return FluidValue.Create(phoneNumber, ctx.Options);
                }
            }
        }

        if (value is IUser user)
        {
            return FluidValue.Create(await _userManager.GetPhoneNumberAsync(user), ctx.Options);
        }

        return NilValue.Instance;
    }
 
}