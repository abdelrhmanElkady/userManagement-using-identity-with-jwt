using dotnetClaimAuthorization.Data;
using dotnetClaimAuthorization.Data.Entities;
using dotnetClaimAuthorization.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;




// for cors
var _loginOrigin = "_localorigin";

var builder = WebApplication.CreateBuilder(args);



// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "please enter token",
        Name = "Authrization",
        Type = SecuritySchemeType.Http,
        BearerFormat ="JWT",
        Scheme = "bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[]{}
        }
    });
});
builder.Services.Configure<JWTConfig>(builder.Configuration.GetSection("JWTConfig"));
builder.Services.AddDbContext<AppDBContext>(opt =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<AppUser,IdentityRole>(opt => { }).AddEntityFrameworkStores<AppDBContext>();

// if you want to add [Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme)] above every endpoint in controller
//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
//{
//    var key = Encoding.ASCII.GetBytes(builder.Configuration["JWTConfig:Key"]);
//    var issure = builder.Configuration["JWTConfig:Issure"];
//    var audience = builder.Configuration["JWTConfig:Audience"];

//    options.TokenValidationParameters = new TokenValidationParameters()
//    {
//        ValidateIssuerSigningKey = true,
//        IssuerSigningKey = new SymmetricSecurityKey(key),
//        ValidateIssuer = true,
//        ValidateAudience = true,
//        RequireExpirationTime = true,
//        ValidIssuer = issure,
//        ValidAudience = audience

//    };
//});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    var key = Encoding.ASCII.GetBytes(builder.Configuration["JWTConfig:Key"]);
    var issure = builder.Configuration["JWTConfig:Issure"];
    var audience = builder.Configuration["JWTConfig:Audience"];

    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidateAudience = true,
        RequireExpirationTime = true,
        ValidIssuer = issure,
        ValidAudience = audience

    };
});

builder.Services.AddCors(options =>
{
    options.AddPolicy(_loginOrigin, builder =>
    {
        builder.AllowAnyOrigin();
        builder.AllowAnyHeader();
        builder.AllowAnyMethod();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.UseCors(_loginOrigin);
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
