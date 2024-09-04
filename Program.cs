using Azure.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
     .AddOpenIdConnect(options =>
     {
         options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
         options.Authority = $"{builder.Configuration["AzureAd:Instance"]}{builder.Configuration["AzureAd:TenantId"]}/v2.0";
         options.ClientId = builder.Configuration["AzureAd:ClientId"];
         options.ClientSecret = builder.Configuration["AzureAd:ClientSecret"];
         options.CallbackPath = builder.Configuration["AzureAd:CallbackPath"];
         options.ResponseMode = OpenIdConnectResponseMode.FormPost;
         options.ResponseType = OpenIdConnectResponseType.Code;
         options.UsePkce = false;
         options.SaveTokens = true;
     })
     .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(builder.Configuration["storageAccountConnectionString"], "dataprotectionblob", "dataprotectionblob")
    .SetApplicationName(builder.Configuration["AppName"])
    .ProtectKeysWithAzureKeyVault(new Uri(builder.Configuration["keyIdentifier"]), new DefaultAzureCredential());

builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});
builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
