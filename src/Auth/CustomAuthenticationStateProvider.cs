using BlazorServer_NET6_Iwanov_Egor.Auth;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly ProtectedSessionStorage _sessionStorage;
    private readonly ProtectedLocalStorage _localStorage;
    private ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());

    public CustomAuthenticationStateProvider(ProtectedSessionStorage sessionStorage, ProtectedLocalStorage localStorage)
    {
        _sessionStorage = sessionStorage;
        _localStorage = localStorage;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var userSessionLocalStorageResult = await _localStorage.GetAsync<UserSession>("UserSession");
            if (userSessionLocalStorageResult.Success && userSessionLocalStorageResult.Value != null)
            {
                var userSession = userSessionLocalStorageResult.Value;
                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.Sid, userSession.Id),
                    new Claim(ClaimTypes.Name, userSession.FirstName),
                    new Claim(ClaimTypes.Email, userSession.Email),
                    new Claim(ClaimTypes.Role, userSession.Role)
                }, "CustomAuth"));

                return new AuthenticationState(claimsPrincipal);
            }

            var userSessionSessionStorageResult = await _sessionStorage.GetAsync<UserSession>("UserSession");
            var userSessionSession = userSessionSessionStorageResult.Success ? userSessionSessionStorageResult.Value : null;
            if (userSessionSession == null)
            {
                return new AuthenticationState(_anonymous);
            }

            var claimsPrincipalSession = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Sid, userSessionSession.Id),
                new Claim(ClaimTypes.Name, userSessionSession.FirstName),
                new Claim(ClaimTypes.Email, userSessionSession.Email),
                new Claim(ClaimTypes.Role, userSessionSession.Role)
            }, "CustomAuth"));

            return new AuthenticationState(claimsPrincipalSession);
        }
        catch
        {
            return new AuthenticationState(_anonymous);
        }
    }

    public async Task UpdateAuthenticationStateAsync(UserSession userSession)
    {
        ClaimsPrincipal claimsPrincipal;

        if (userSession != null)
        {
            await _localStorage.SetAsync("UserSession", userSession);
            await _sessionStorage.SetAsync("UserSession", userSession);

            claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Sid, userSession.Id),
                new Claim(ClaimTypes.Name, userSession.FirstName),
                new Claim(ClaimTypes.Email, userSession.Email),
                new Claim(ClaimTypes.Role, userSession.Role)
            }));
        }
        else
        {
            await _localStorage.DeleteAsync("UserSession");
            await _sessionStorage.DeleteAsync("UserSession");
            claimsPrincipal = _anonymous;
        }

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
    }
}