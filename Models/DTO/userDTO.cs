namespace dotnetClaimAuthorization.DTO
{
    public class userDTO
    {

        public userDTO(string fullName,string email, DateTime dateCreated,DateTime dateModified, List<string> roles)
        {
            FullName = fullName;
            Email = email;
            DateCreated = dateCreated;
            DateModified = dateModified;
            Roles = roles;
        }
        public string FullName { get; set; }
        public string Email { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DateModified { get; set; }
        public string Token { get; set; }
        public List<string> Roles { get; set; }

    }
}
