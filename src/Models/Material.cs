using System;
using System.Collections.Generic;

namespace BlazorServer_NET6_Iwanov_Egor.Models;

public partial class Material
{
    public int MaterialId { get; set; }

    public string Name { get; set; } = null!;

    public string? Description { get; set; }

    public virtual ICollection<Course> Courses { get; } = new List<Course>();
}
