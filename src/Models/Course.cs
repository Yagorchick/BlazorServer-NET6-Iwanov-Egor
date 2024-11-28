using System;
using System.Collections.Generic;

namespace BlazorServer_NET6_Iwanov_Egor.Models;

public partial class Course
{
    public int CourseId { get; set; }

    public string Title { get; set; } = null!;

    public string? Description { get; set; }

    public int? InstructorId { get; set; }

    public DateTime? CreatedAt { get; set; }

    public virtual ICollection<Enrollment> Enrollments { get; } = new List<Enrollment>();

    public virtual User? Instructor { get; set; }

    public virtual ICollection<Review> Reviews { get; } = new List<Review>();

    public virtual ICollection<Material> Materials { get; } = new List<Material>();
}
