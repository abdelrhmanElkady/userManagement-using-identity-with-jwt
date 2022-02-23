using dotnetClaimAuthorization.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace dotnetClaimAuthorization.Data
{
    public class AppDBContext : IdentityDbContext<AppUser, IdentityRole, string>
    {
        public AppDBContext(DbContextOptions options) : base(options)
        {
        }
    }
}
