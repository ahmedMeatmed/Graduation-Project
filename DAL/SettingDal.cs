using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;
using System.Collections.Generic;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling application settings and configuration operations
    /// </summary>
    public static class SettingDal
    {
        /// <summary>
        /// Retrieves all settings from the database
        /// </summary>
        /// <returns>A SettingCollection containing all application settings</returns>
        public static SettingCollection GetAll()
        {
            SettingCollection collection = new SettingCollection();
            DataTable dt = DBL.DBL.ExecuteQuery("SELECT * FROM Settings");
            for (int i = 0; i < dt.Rows.Count; i++)
            {
                collection.Add(new Settings(
                    (int)dt.Rows[i]["SettingID"],
                    dt.Rows[i]["SettingKey"].ToString(),
                    dt.Rows[i]["SettingValue"].ToString(),
                    dt.Rows[i]["DataType"].ToString(),
                    dt.Rows[i]["Category"].ToString(),
                    dt.Rows[i]["Description"].ToString(),
                    (DateTime)dt.Rows[i]["LastModified"]  // REMOVED EXTRA SPACE
                ));
            }
            return collection;
        }

        /// <summary>
        /// Retrieves a specific setting by its unique identifier
        /// </summary>
        /// <param name="id">The SettingID of the setting to retrieve</param>
        /// <returns>A Settings object if found, otherwise null</returns>
        public static Settings GetById(int id)
        {
            Settings setting = null;
            try
            {
                string query = "SELECT * FROM Settings WHERE SettingID = @SettingID";
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@SettingID", SqlDbType.Int) { Value = id }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    setting = new Settings(
                        (int)dt.Rows[0]["SettingID"],
                        dt.Rows[0]["SettingKey"].ToString(),  // FIXED: Use SettingKey not SettingName
                        dt.Rows[0]["SettingValue"].ToString(),
                        dt.Rows[0]["DataType"].ToString(),
                        dt.Rows[0]["Category"].ToString(),
                        dt.Rows[0]["Description"].ToString(),
                        (DateTime)dt.Rows[0]["LastModified"]  // REMOVED EXTRA SPACE
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching setting by ID: " + ex.Message);
            }
            return setting;
        }

        /// <summary>
        /// Retrieves a specific setting by its key name
        /// </summary>
        /// <param name="name">The SettingKey of the setting to retrieve</param>
        /// <returns>A Settings object if found, otherwise null</returns>
        public static Settings GetByName(string name)
        {
            Settings setting = null;
            try
            {
                string query = "SELECT * FROM Settings WHERE SettingKey = @SettingKey";  // FIXED: Consistent parameter name
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@SettingKey", SqlDbType.NVarChar, 100) { Value = name }  // Match VARCHAR(100)
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    setting = new Settings(
                        (int)dt.Rows[0]["SettingID"],
                        dt.Rows[0]["SettingKey"].ToString(),
                        dt.Rows[0]["SettingValue"].ToString(),
                        dt.Rows[0]["DataType"].ToString(),
                        dt.Rows[0]["Category"].ToString(),
                        dt.Rows[0]["Description"].ToString(),
                        (DateTime)dt.Rows[0]["LastModified"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching setting by name: " + ex.Message);
            }
            return setting;
        }

        /// <summary>
        /// Inserts a new setting into the database
        /// </summary>
        /// <param name="settingKey">The unique key identifier for the setting</param>
        /// <param name="settingValue">The value of the setting</param>
        /// <param name="dataType">The data type of the setting value (e.g., string, int, bool)</param>
        /// <param name="category">The category grouping for the setting (e.g., Network, Security, General)</param>
        /// <param name="desc">The description of what the setting controls</param>
        /// <param name="lastModified">The timestamp when the setting was last modified</param>
        /// <returns>True if the insertion was successful, otherwise false</returns>
        public static bool Insert(string settingKey, string settingValue, string dataType, string category, string desc, DateTime lastModified)
        {
            string query = "INSERT INTO Settings (SettingKey, SettingValue, DataType, Category, Description, LastModified) VALUES (@SettingKey, @SettingValue, @DataType, @Category, @Description, @LastModified)";
            SqlParameter[] parameters = new SqlParameter[]
            {
                new SqlParameter("@SettingKey", SqlDbType.NVarChar, 100) { Value = settingKey },
                new SqlParameter("@SettingValue", SqlDbType.NVarChar, -1) { Value = settingValue },  // -1 for MAX
                new SqlParameter("@DataType", SqlDbType.NVarChar, 50) { Value = dataType },
                new SqlParameter("@Category", SqlDbType.NVarChar, 50) { Value = category },
                new SqlParameter("@Description", SqlDbType.NVarChar, 255) { Value = desc },
                new SqlParameter("@LastModified", SqlDbType.DateTime) { Value = lastModified }
            };

            return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
        }

        /// <summary>
        /// Updates an existing setting in the database
        /// </summary>
        /// <param name="id">The unique identifier of the setting to update</param>
        /// <param name="settingKey">The updated setting key</param>
        /// <param name="settingValue">The updated setting value</param>
        /// <param name="dataType">The updated data type</param>
        /// <param name="category">The updated category</param>
        /// <param name="desc">The updated description</param>
        /// <param name="lastModified">The updated modification timestamp</param>
        /// <returns>The number of rows affected by the update operation</returns>
        public static int Update(int id, string settingKey, string settingValue, string dataType, string category, string desc, DateTime lastModified)
        {
            string query = "UPDATE Settings SET SettingKey = @SettingKey, SettingValue = @SettingValue, DataType = @DataType, Category = @Category, Description = @Description, LastModified = @LastModified WHERE SettingID = @SettingID";
            SqlParameter[] parameters = new SqlParameter[]
            {
                new SqlParameter("@SettingKey", SqlDbType.NVarChar, 100) { Value = settingKey },
                new SqlParameter("@SettingValue", SqlDbType.NVarChar, -1) { Value = settingValue },
                new SqlParameter("@DataType", SqlDbType.NVarChar, 50) { Value = dataType },
                new SqlParameter("@Category", SqlDbType.NVarChar, 50) { Value = category },
                new SqlParameter("@Description", SqlDbType.NVarChar, 255) { Value = desc },
                new SqlParameter("@LastModified", SqlDbType.DateTime) { Value = lastModified },
                new SqlParameter("@SettingID", SqlDbType.Int) { Value = id }
            };

            return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
        }

        /// <summary>
        /// Deletes a setting from the database
        /// </summary>
        /// <param name="id">The unique identifier of the setting to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int id)
        {
            string query = "DELETE FROM Settings WHERE SettingID = @SettingID";
            SqlParameter[] parameters = new SqlParameter[]
            {
                new SqlParameter("@SettingID", SqlDbType.Int) { Value = id }
            };

            return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
        }

        /// <summary>
        /// Retrieves the internal IP address prefix setting used for network configuration
        /// </summary>
        /// <returns>The internal IP prefix value if found, otherwise null</returns>
        public static string GetInternalIpPrefix()
        {
            string ip = null;
            try
            {
                string query = "SELECT SettingValue FROM Settings WHERE SettingKey = @SettingKey";  // FIXED: Consistent parameter name
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@SettingKey", SqlDbType.NVarChar, 100) { Value = "InternalIpPrefix" }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    ip = dt.Rows[0]["SettingValue"].ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching internal IP prefix: " + ex.Message);
            }
            return ip;
        }
    }
}