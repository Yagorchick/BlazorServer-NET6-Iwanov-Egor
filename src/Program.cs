using BlazorServer_NET6_Iwanov_Egor.Auth;
using BlazorServer_NET6_Iwanov_Egor.Data;
using BlazorServer_NET6_Iwanov_Egor.Models;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;

namespace BlazorServer_NET6_Iwanov_Egor
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var connectionString = builder.Configuration.GetConnectionString("Server=sql.bsite.net\\MSSQL2016;Database=yagorchick_;User Id=yagorchick_;Password=23042003;TrustServerCertificate=true;");
            Console.WriteLine($"Connection String: {connectionString}");

            builder.Services.AddDbContext<YagorchickContext>(options =>
                options.UseSqlServer("Server=sql.bsite.net\\MSSQL2016;Database=yagorchick_;User Id=yagorchick_;Password=23042003;TrustServerCertificate=true;"));

            builder.Services.AddAuthenticationCore();
            //builder.Services.AddRazorComponents()
                //.AddInteractiveServerComponents();
            builder.Services.AddRazorPages();
            builder.Services.AddServerSideBlazor();


            builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();
            builder.Services.AddScoped<ProtectedSessionStorage>();
            builder.Services.AddScoped<ProtectedLocalStorage>();

            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            //app.UseAntiforgery();

            //app.MapRazorComponents<App>()
                //.AddInteractiveServerRenderMode();

            app.MapRazorPages();
            // app.MapBlazorHub();
            app.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Program>();
            });

    }
}