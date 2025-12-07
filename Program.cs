using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Read env vars (fallbacks for local dev)
var port = Environment.GetEnvironmentVariable("PORT") ?? "5000";
var secret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "dev_secret_change_me";
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Це те, що виправляється. Потрібно вказати, що це TokenValidationParameters
        // У вашому коді, здається, ви просто не вказали назви властивостей,
        // а потім компілятор почав бачити ці назви як неіснуючі змінні.
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ClockSkew = TimeSpan.Zero // стараємось уникати "допуску" для exp
    };
});

// Authorization policy for admin
builder.Services.AddAuthorization(options =>
{
    // We will issue role using ClaimTypes.Role
    options.AddPolicy("AdminOnly", policy => policy.RequireClaim(ClaimTypes.Role, "admin"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// In-memory pseudo-user store
var users = new[]
{
    new { Id = 1, Email = "admin@example.com", Password = "admin123", Role = "admin" },
    new { Id = 2, Email = "user@example.com", Password = "user123", Role = "user" }
};

app.MapPost("/login", (HttpRequest request) =>
{
    // Read JSON body
    var body = request.ReadFromJsonAsync<Dictionary<string, string>>().Result ?? new Dictionary<string, string>();
    body.TryGetValue("email", out var email);
    body.TryGetValue("password", out var password);

    var user = users.FirstOrDefault(u => u.Email == email && u.Password == password);
    if (user is null)
        return Results.Unauthorized();

    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        // store role as ClaimTypes.Role so Policy RequireClaim works
        new Claim(ClaimTypes.Role, user.Role)
    };

    var jwt = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(15),
        signingCredentials: creds
    );

    var token = new JwtSecurityTokenHandler().WriteToken(jwt);

    return Results.Json(new { access_token = token, token_type = "Bearer", expires_in = 900 });
});

// Захищений роут, що вимагає аутентифікації
app.MapGet("/profile", (ClaimsPrincipal user) =>
{
    var sub = user.FindFirstValue(JwtRegisteredClaimNames.Sub);
    var role = user.FindFirstValue(ClaimTypes.Role);
    // Додаємо вивід даних або іншу логіку для завершення методу
    return Results.Json(new { sub = sub, role = role });
}).RequireAuthorization(); // <--- Необхідно додати, щоб роут вимагав токен

// Додаємо захищений роут, що вимагає ролі "admin"
app.MapGet("/admin", () => Results.Ok("Welcome, Admin!"))
    .RequireAuthorization("AdminOnly");

// Видаляємо дублювання 'app.Run()' і додаємо використання 'port'
app.Run($"http://localhost:{port}");

