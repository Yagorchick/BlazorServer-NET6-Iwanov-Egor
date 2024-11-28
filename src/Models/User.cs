using System;
using System.Collections.Generic;

namespace BlazorServer_NET6_Iwanov_Egor.Models;

public partial class User
{
    public int UserId { get; set; }

    public string FirstName { get; set; } = null!;

    public string Username { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string PasswordHash { get; set; } = null!;

    public DateTime CreatedAt { get; set; }

    public string? Role { get; set; }

    public virtual ICollection<Course> Courses { get; } = new List<Course>();

    public virtual ICollection<Enrollment> Enrollments { get; } = new List<Enrollment>();

    public virtual ICollection<Review> Reviews { get; } = new List<Review>();
}
