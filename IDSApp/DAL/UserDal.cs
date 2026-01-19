using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for user management operations in the database.
    /// </summary>
    internal class UserDal
    {
        /// <summary>
        /// Retrieves all users from the database.
        /// </summary>
        /// <returns>A collection of Users objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static UserCollection GetAll()
        {
            UserCollection userList = new UserCollection();

            try
            {
                string query = "SELECT * FROM Users";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    Users user = new Users(
                        (int)row["UserID"],
                        row["Username"].ToString(),
                        row["PasswordHash"].ToString(),
                        row["Role"].ToString()
                    );
                    userList.Add(user);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching all users: " + ex.Message);
            }

            return userList;
        }

        /// <summary>
        /// Inserts a new user into the database after checking for existing username and hashing the password.
        /// </summary>
        /// <param name="username">The username for the new user.</param>
        /// <param name="password">The plain text password to be hashed before storage.</param>
        /// <param name="role">The role assigned to the user (e.g., Admin, User).</param>
        /// <returns>true if the user was successfully inserted; false if the username already exists or an error occurred.</returns>
        public static bool Insert(string username, string password, string role)
        {
            try
            {
                // Check if user already exists using the fn_UserExists function
                string checkUserExistsQuery = "SELECT dbo.fn_UserExists(@Username)";

                SqlParameter[] checkUserParameters = new SqlParameter[]
                {
                new SqlParameter("@Username", SqlDbType.NVarChar, 50) { Value = username }
                };

                int userExists = (int)DBL.DBL.ExecuteScalarWithParameters(checkUserExistsQuery, checkUserParameters);

                // If user exists, return false
                if (userExists == 1)
                {
                    Console.WriteLine("User already exists.");
                    return false;
                }

                // If user doesn't exist, hash the password and insert the new user
                string insertQuery = "INSERT INTO Users (Username, Password, Role) " +
                                     "VALUES (@Username, dbo.fn_HashPassword(@Password), @Role)";

                SqlParameter[] insertParameters = new SqlParameter[]
                {
                new SqlParameter("@Username", SqlDbType.NVarChar, 255) { Value = username },
                new SqlParameter("@Password", SqlDbType.NVarChar, 255) { Value = password }, // The password will be hashed in SQL
                new SqlParameter("@Role", SqlDbType.NVarChar, 50) { Value = role }
                };

                // Execute the insert query
                return DBL.DBL.ExecuteNonQueryWithParameters(insertQuery, insertParameters) > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting user: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing user's information including username, password, and role.
        /// </summary>
        /// <param name="userId">The UserID of the user to update.</param>
        /// <param name="username">The new username.</param>
        /// <param name="password">The new plain text password to be hashed before storage.</param>
        /// <param name="role">The new role for the user.</param>
        /// <returns>true if the user was successfully updated; false if the user doesn't exist or an error occurred.</returns>
        public static bool Update(int userId, string username, string password, string role)
        {
            try
            {
                // Check if the user exists using the userId (or username if you prefer)
                string checkUserExistsQuery = "SELECT COUNT(1) FROM Users WHERE UserID = @UserID";

                SqlParameter[] checkUserParameters = new SqlParameter[]
                {
                new SqlParameter("@UserID", SqlDbType.Int) { Value = userId }
                };

                int userExists = (int)DBL.DBL.ExecuteScalarWithParameters(checkUserExistsQuery, checkUserParameters);

                if (userExists == 0)
                {
                    Console.WriteLine("User does not exist.");
                    return false; // User does not exist
                }

                // If the user exists, hash the new password and update the user
                string updateQuery = "UPDATE Users " +
                                     "SET Username = @Username, " +
                                     "PasswordHash = dbo.fn_HashPassword(@Password), " + // Hash the new password before updating
                                     "Role = @Role " +
                                     "WHERE UserID = @UserID";

                SqlParameter[] updateParameters = new SqlParameter[]
                {
                new SqlParameter("@Username", SqlDbType.NVarChar, 255) { Value = username },
                new SqlParameter("@Password", SqlDbType.NVarChar, 255) { Value = password }, // Password to be hashed in SQL
                new SqlParameter("@Role", SqlDbType.NVarChar, 50) { Value = role },
                new SqlParameter("@UserID", SqlDbType.Int) { Value = userId }
                };

                // Execute the update query
                return DBL.DBL.ExecuteNonQueryWithParameters(updateQuery, updateParameters) > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating user: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a user from the database by their UserID.
        /// </summary>
        /// <param name="userId">The UserID of the user to delete.</param>
        /// <returns>true if the user was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int userId)
        {
            try
            {
                string query = "DELETE FROM Users WHERE UserID = @UserID";
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@UserID", SqlDbType.Int) { Value = userId }
                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting user: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a specific user by their unique identifier.
        /// </summary>
        /// <param name="userId">The UserID of the user to retrieve.</param>
        /// <returns>A Users object if found; otherwise, null.</returns>
        public static Users GetById(int userId)
        {
            Users user = null;

            try
            {
                string query = "SELECT * FROM Users WHERE UserID = @UserID";
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@UserID", SqlDbType.Int) { Value = userId }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    user = new Users(
                        (int)row["UserID"],
                        row["Username"].ToString(),
                        row["PasswordHash"].ToString(),
                        row["Role"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching user by UserID: " + ex.Message);
            }

            return user;
        }

        /// <summary>
        /// Retrieves all users with a specific role from the database.
        /// </summary>
        /// <param name="role">The role to filter users by (e.g., Admin, User).</param>
        /// <returns>A collection of Users objects with the specified role. Returns an empty collection if no users are found or if an error occurs.</returns>
        public static UserCollection GetByRole(string role)
        {
            UserCollection userList = new UserCollection();

            try
            {
                string query = "SELECT * FROM Users WHERE Role = @Role";
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@Role", SqlDbType.NVarChar, 50) { Value = role }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                foreach (DataRow row in dt.Rows)
                {
                    Users user = new Users(
                        (int)row["UserID"],
                        row["Username"].ToString(),
                        row["Password"].ToString(),
                        row["Role"].ToString()
                    );
                    userList.Add(user);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching users by role: " + ex.Message);
            }

            return userList;
        }
    }
}