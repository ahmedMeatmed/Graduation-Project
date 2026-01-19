    using IDSApp.Collection;
    using IDSApp.Entity;
    using IDSApp.Helper;
    using Microsoft.Data.SqlClient;
    using System;
    using System.Collections.Generic;
    using System.Data;

    namespace IDSApp.DAL
    {
        /// <summary>
        /// Data Access Layer for handling Alert-related database operations
        /// </summary>
        internal class AlertDal
        {
            /// <summary>
            /// Retrieves all alerts from the database
            /// </summary>
            /// <returns>An AlertCollection containing all alerts</returns>
            public static AlertCollection GetAll()
            {
                AlertCollection collection = new AlertCollection();
                DataTable dt = DBL.DBL.ExecuteQuery("SELECT * FROM Alerts");

                foreach (DataRow row in dt.Rows)
                {
                    collection.Add(new Alerts(
                        (int)row["AlertID"],
                        (int)row["LogID"],
                        row["Message"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["Status"].ToString(),
                        DAL.LogDal.GetById((int)row["LogId"]),
                        row["AttackType"].ToString(),
                        Enum.Parse<Severity>(row["Severity"].ToString(), true), // parse string to enum
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        row["AssignedTo"].ToString()
                    ));
                }

                return collection;
            }

            /// <summary>
            /// Retrieves a specific alert by its unique identifier
            /// </summary>
            /// <param name="id">The AlertID of the alert to retrieve</param>
            /// <returns>An Alerts object if found, otherwise null</returns>
            public static Alerts GetById(int id)
            {
                Alerts alert = null;
                try
                {
                    string query = "SELECT * FROM Alerts WHERE AlertID = @AlertID";
                    SqlParameter[] parameters = new SqlParameter[]
                    {
                        new SqlParameter("@AlertID", SqlDbType.Int) { Value = id }
                    };

                    DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                    if (dt.Rows.Count > 0)
                    {
                        DataRow row = dt.Rows[0];
                        alert = new Alerts(
                            (int)row["AlertID"],
                            (int)row["LogID"],
                            row["Message"].ToString(),
                            Convert.ToDateTime(row["Timestamp"]),
                            row["Status"].ToString(),
                            DAL.LogDal.GetById((int)row["LogId"]),
                            row["AttackType"].ToString(),
                            Enum.Parse<Severity>(row["Severity"].ToString(), true),
                            row["SourceIP"].ToString(),
                            row["DestinationIP"].ToString(),
                            row["AssignedTo"].ToString()
                        );
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error fetching alert by ID: " + ex.Message);
                }
                return alert;
            }

            /// <summary>
            /// Retrieves an alert by its timestamp (matches by date portion only)
            /// </summary>
            /// <param name="timeStamp">The timestamp to search for (time portion is ignored)</param>
            /// <returns>An Alerts object if found, otherwise null</returns>
            public static Alerts GetByTimeStamp(DateTime timeStamp)
            {
                Alerts alert = null;
                try
                {
                    string query = "SELECT * FROM Alerts WHERE CAST(Timestamp AS DATE) = @timestamp";
                    SqlParameter[] parameters = new SqlParameter[]
                    {
                        new SqlParameter("@timestamp", SqlDbType.Date) { Value = timeStamp.Date }
                    };

                    DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                    if (dt.Rows.Count > 0)
                    {
                        DataRow row = dt.Rows[0];
                        alert = new Alerts(
                            (int)row["AlertID"],
                            (int)row["LogID"],
                            row["Message"].ToString(),
                            Convert.ToDateTime(row["Timestamp"]),
                            row["Status"].ToString(),
                            DAL.LogDal.GetById((int)row["LogId"]),
                            row["AttackType"].ToString(),
                            Enum.Parse<Severity>(row["Severity"].ToString(), true),
                            row["SourceIP"].ToString(),
                            row["DestinationIP"].ToString(),
                            row["AssignedTo"].ToString()
                        );
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error fetching alert by timestamp: " + ex.Message);
                }
                return alert;
            }

            /// <summary>
            /// Inserts a new alert into the database
            /// </summary>
            /// <param name="logId">The associated log identifier</param>
            /// <param name="message">The alert message</param>
            /// <param name="attackType">The type of attack detected</param>
            /// <param name="severity">The severity level (Low, Medium, High)</param>
            /// <param name="sourceIp">The source IP address</param>
            /// <param name="destinationIp">The destination IP address</param>
            /// <param name="assignedTo">The person or team assigned to handle the alert</param>
            /// <param name="timestamp">The timestamp when the alert occurred</param>
            /// <param name="status">The current status of the alert</param>
            /// <returns>True if the insertion was successful, otherwise false</returns>
            public static bool Insert(int logId, string message, string attackType, string severity, string sourceIp, string destinationIp, string assignedTo, DateTime timestamp, string status)
            {
                var validSeverities = new[] { "Low", "Medium", "High" };
                if (!validSeverities.Contains(severity))
                {
                    severity = "Medium"; // Default value
                    OptimizedLogger.LogDebug($"Invalid severity '{severity}' replaced with 'Medium' for log {logId}");
                }

                string query = @"INSERT INTO Alerts 
                        (LogID, Message, AttackType, Severity, SourceIP, DestinationIP, AssignedTo, Timestamp, Status) 
                        VALUES (@LogID, @Message, @AttackType, @Severity, @SourceIP, @DestinationIP, @AssignedTo, @Timestamp, @Status)";

                SqlParameter[] parameters = new SqlParameter[]
                {
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@Message", SqlDbType.NVarChar, 255) { Value = message },
            new SqlParameter("@AttackType", SqlDbType.NVarChar, 100) { Value = attackType ?? (object)DBNull.Value },
            new SqlParameter("@Severity", SqlDbType.NVarChar, 20) { Value = severity },
            new SqlParameter("@SourceIP", SqlDbType.NVarChar, 45) { Value = sourceIp ?? (object)DBNull.Value },
            new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 45) { Value = destinationIp ?? (object)DBNull.Value },
            new SqlParameter("@AssignedTo", SqlDbType.NVarChar, 100) { Value = assignedTo ?? (object)DBNull.Value },
            new SqlParameter("@Timestamp", SqlDbType.DateTime) { Value = timestamp },
            new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }

            /// <summary>
            /// Updates an existing alert in the database
            /// </summary>
            /// <param name="alertId">The unique identifier of the alert to update</param>
            /// <param name="logId">The associated log identifier</param>
            /// <param name="message">The updated alert message</param>
            /// <param name="attackType">The updated attack type</param>
            /// <param name="severity">The updated severity level</param>
            /// <param name="sourceIp">The updated source IP address</param>
            /// <param name="destinationIp">The updated destination IP address</param>
            /// <param name="assignedTo">The updated assignee</param>
            /// <param name="timestamp">The updated timestamp</param>
            /// <param name="status">The updated status</param>
            /// <returns>True if the update was successful, otherwise false</returns>
            public static bool Update(int alertId, int logId, string message, string attackType, string severity, string sourceIp, string destinationIp, string assignedTo, DateTime timestamp, string status)
            {
                string query = @"UPDATE Alerts 
                                 SET LogID = @LogID, Message = @Message, AttackType = @AttackType, Severity = @Severity, 
                                     SourceIP = @SourceIP, DestinationIP = @DestinationIP, AssignedTo = @AssignedTo, 
                                     Timestamp = @Timestamp, Status = @Status 
                                 WHERE AlertID = @AlertID";

                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@AlertID", SqlDbType.Int) { Value = alertId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Message", SqlDbType.NVarChar, 255) { Value = message },
                    new SqlParameter("@AttackType", SqlDbType.NVarChar, 100) { Value = attackType ?? (object)DBNull.Value },
                    new SqlParameter("@Severity", SqlDbType.NVarChar, 20) { Value = severity },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 45) { Value = sourceIp ?? (object)DBNull.Value },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 45) { Value = destinationIp ?? (object)DBNull.Value },
                    new SqlParameter("@AssignedTo", SqlDbType.NVarChar, 100) { Value = assignedTo ?? (object)DBNull.Value },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime) { Value = timestamp },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }

            /// <summary>
            /// Deletes an alert from the database
            /// </summary>
            /// <param name="alertId">The unique identifier of the alert to delete</param>
            /// <returns>True if the deletion was successful, otherwise false</returns>
            public static bool Delete(int alertId)
            {
                string query = "DELETE FROM Alerts WHERE AlertID = @AlertID";

                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@AlertID", SqlDbType.Int) { Value = alertId }
                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }

            /// <summary>
            /// Retrieves all alerts associated with a specific log identifier
            /// </summary>
            /// <param name="logId">The log identifier to search for</param>
            /// <returns>An AlertCollection containing alerts for the specified log</returns>
            internal static AlertCollection GetByLogId(int logId)
            {
                AlertCollection alertsList = new AlertCollection();

                try
                {
                    string query = "SELECT * FROM Alerts WHERE LogID = @LogID";
                    SqlParameter[] parameters = new SqlParameter[]
                    {
                        new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                    };

                    DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                    foreach (DataRow row in dt.Rows)
                    {
                        Alerts alert = new Alerts(
                            (int)row["AlertID"],
                            (int)row["LogID"],
                            row["Message"].ToString(),
                            Convert.ToDateTime(row["Timestamp"]),
                            row["Status"].ToString(),
                            DAL.LogDal.GetById((int)row["LogID"]),
                            row["AttackType"].ToString(),
                            Enum.Parse<Severity>(row["Severity"].ToString(), true),
                            row["SourceIP"].ToString(),
                            row["DestinationIP"].ToString(),
                            row["AssignedTo"].ToString()
                        );

                        alertsList.Add(alert);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error fetching alerts by LogID: " + ex.Message);
                }

                return alertsList;
            }
        }
    }