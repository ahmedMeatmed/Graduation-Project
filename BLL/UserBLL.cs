using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for user management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for user-related operations.
    /// </summary>
    internal class UserBLL
    {
        /// <summary>
        /// Retrieves all users from the system.
        /// </summary>
        /// <returns>A collection of Users objects containing all users in the system.</returns>
        public static UserCollection GetAll()
        {
            return DAL.UserDal.GetAll();
        }

        /// <summary>
        /// Creates a new user in the system with password hashing.
        /// </summary>
        /// <param name="username">The unique username for the new user.</param>
        /// <param name="password">The plain text password to be hashed before storage.</param>
        /// <param name="role">The role assigned to the user (e.g., Admin, User, Analyst).</param>
        /// <returns>true if the user was successfully created; false if the username already exists or an error occurred.</returns>
        public static bool Insert(string username, string password, string role)
        {
            return DAL.UserDal.Insert(username, password, role);
        }

        /// <summary>
        /// Updates an existing user's information including password re-hashing.
        /// </summary>
        /// <param name="userId">The UserID of the user to update.</param>
        /// <param name="username">The new username.</param>
        /// <param name="password">The new plain text password to be hashed.</param>
        /// <param name="role">The new role for the user.</param>
        /// <returns>true if the user was successfully updated; false if the user doesn't exist or an error occurred.</returns>
        public static bool Update(int userId, string username, string password, string role)
        {
            return DAL.UserDal.Update(userId, username, password, role);
        }

        /// <summary>
        /// Deletes a user from the system.
        /// </summary>
        /// <param name="userId">The UserID of the user to delete.</param>
        /// <returns>true if the user was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int userId)
        {
            return DAL.UserDal.Delete(userId);
        }

        /// <summary>
        /// Retrieves a specific user by their unique identifier.
        /// </summary>
        /// <param name="userId">The UserID of the user to retrieve.</param>
        /// <returns>A Users object if found; otherwise, null.</returns>
        public static Users GetById(int userId)
        {
            return DAL.UserDal.GetById(userId);
        }

        /// <summary>
        /// Retrieves all users with a specific role from the system.
        /// </summary>
        /// <param name="role">The role to filter users by (e.g., Admin, User, Analyst).</param>
        /// <returns>A collection of Users objects with the specified role.</returns>
        public static UserCollection GetByRole(string role)
        {
            return DAL.UserDal.GetByRole(role);
        }
    }
}