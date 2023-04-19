using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Serilog;
using System.Text;

const string DefaultCorsPolicyName = "Dev";

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((hostBuilderContext, loggerConfiguration) => loggerConfiguration.ReadFrom.Configuration(hostBuilderContext.Configuration));

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // SameSiteMode.None is required to support SAML SSO.
    options.MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.None;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    // Use a unique identity cookie name rather than sharing the cookie across applications in the domain.
    options.Cookie.Name = builder.Configuration["JWT:CookieName"];

    // SameSiteMode.None is required to support SAML logout.
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
});

// Optionally add support for JWT bearer tokens.
// This is required only if JWT bearer tokens are used to authorize access to a web API.
// It's not required for SAML SSO.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Events = new JwtBearerEvents()
        {
            OnMessageReceived = context =>
            {
                if (context.Request.Cookies.ContainsKey(builder.Configuration["JWT:CookieName"]))
                {
                    context.Token = context.Request.Cookies[builder.Configuration["JWT:CookieName"]];
                }

                return Task.CompletedTask;
            },

            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    // Send a signal to the client that the JWT has expired:
                    // - Add a header to the response to indicate the token has expired
                    // - Use it to perform a desired action on the client
                    // This is just an example of one approach to handle this event on the client.
                    context.Response.Headers.Add("token-expired", "true");
                    context.Response.Headers.Add("access-control-expose-headers", "token-expired");
                }

                return Task.CompletedTask;
            }
        };
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JWT:Issuer"],
            ValidAudience = builder.Configuration["JWT:Issuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
        };
    });

// Optionally add cross-origin request sharing services.
// This is only required for the web API.
// It's not required for SAML SSO.
//builder.Services.AddCors(options =>
//{
//    options.AddPolicy(DefaultCorsPolicyName,
//    builder =>
//    {
//        //builder.WithOrigins("http://localhost:4200", "https://localhost:4200");
//        builder.AllowAnyOrigin();
//        builder.AllowAnyMethod();
//        builder.AllowAnyHeader();
//        //builder.AllowCredentials();
//    });
//});

builder.Services.AddCors(options =>
  options.AddPolicy(DefaultCorsPolicyName, builder =>
  {
      // Allow multiple methods
      builder.WithMethods("GET", "POST", "PATCH", "DELETE", "OPTIONS")
        //.WithHeaders(
        //  HeaderNames.Accept,
        //  HeaderNames.ContentType,
        //  "ngrok-skip-browser-warning")
        .AllowAnyHeader()
        .AllowCredentials()
        .SetIsOriginAllowed(origin =>
        {
            if (string.IsNullOrWhiteSpace(origin)) return false;
            // Only add this to allow testing with localhost, remove this line in production!
            if (origin.ToLower().Contains("localhost")) return true;
            if (origin.ToLower().Contains("google")) return true;
            // Insert your production domain here.
            if (origin.ToLower().Contains(".ngrok-free.app")) return true;
            return false;
        });
  })
);

// Add SAML SSO services.
builder.Services.AddSaml(builder.Configuration.GetSection("SAML"));


//builder.Services.AddAntiforgery(options =>
//{
//    options.HeaderName = builder.Configuration["JWT:CookieName"];
//    options.Cookie.Name = builder.Configuration["JWT:CookieName"];
//    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
//});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();

app.UseCors(DefaultCorsPolicyName);

app.MapControllers();

app.Run();
