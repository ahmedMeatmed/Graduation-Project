using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a system user in the IDS application.
    /// Contains information about the user's ID, name, password, and role.
    /// </summary>
    internal class Users
    {
        private int id;
        private string name;
        private string password;
        private string role;

        /// <summary>
        /// Gets or sets the unique identifier of the user.
        /// </summary>
        public int Id { get => id; set => id = value; }

        /// <summary>
        /// Gets or sets the name of the user.
        /// </summary>
        public string Name { get => name; set => name = value; }

        /// <summary>
        /// Gets or sets the password of the user.
        /// </summary>
        public string Password { get => password; set => password = value; }

        /// <summary>
        /// Gets or sets the role of the user (e.g., Admin, Operator).
        /// </summary>
        public string Role { get => role; set => role = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Users"/> class with specified values.
        /// </summary>
        /// <param name="id">The unique identifier of the user.</param>
        /// <param name="name">The name of the user.</param>
        /// <param name="password">The password of the user.</param>
        /// <param name="role">The role of the user.</param>
        internal Users(int id, string name, string password, string role)
        {
            this.id = id;
            this.name = name;
            this.password = password;
            this.role = role;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Users"/> class by copying another instance.
        /// </summary>
        /// <param name="u">The <see cref="Users"/> instance to copy.</param>
        internal Users(Users u)
        {
            this.id = u.id;
            this.name = u.name;
            this.password = u.password;
            this.role = u.role;
        }

        /// <summary>
        /// Creates a deep copy of the current <see cref="Users"/> instance.
        /// </summary>
        /// <returns>A new <see cref="Users"/> object identical to the current instance.</returns>
        public Users Clone()
        {
            return new Users(this);
        }
    }
}
