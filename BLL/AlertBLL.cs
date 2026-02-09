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
    /// Provides business logic layer operations for alert management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for alert-related operations.
    /// </summary>
    internal static class AlertBLL
    {
        /// <summary>
            /// Retrieves all alerts from the system.
            /// </summary>
            /// <returns>A collection of Alert objects containing all alerts in the system.</returns>
        public static AlertCollection GetAll()
        {
            return DAL.AlertDal.GetAll();
        }

        /// <summary>
            /// Retrieves a specific alert by its unique identifier.
            /// </summary>
            /// <param name="id">The AlertID of the alert to retrieve.</param>
            /// <returns>An Alerts object if found; otherwise, null.</returns>
        public static Alerts GetById(int id)
        {
            return DAL.AlertDal.GetById(id);
        }

        /// <summary>
            /// Retrieves alerts based on their timestamp.
            /// </summary>
            /// <param name="timeStamp">The timestamp to search for alerts.</param>
            /// <returns>An Alerts object matching the specified timestamp if found; otherwise, null.</returns>
        public static Alerts GetByTimeStamp(DateTime timeStamp)
        {
            return DAL.AlertDal.GetByTimeStamp(timeStamp);
        }

        /// <summary>
            /// Creates a new alert in the system.
            /// </summary>
            /// <param name="logId">The associated LogID from the original log entry.</param>
            /// <param name="message">The alert message describing the security event.</param>
            /// <param name="attackType">The type of attack detected (e.g., SQL Injection, DDoS).</param>
            /// <param name="severity">The severity level of the alert (e.g., Low, Medium, High, Critical).</param>
            /// <param name="sourceIp">The source IP address associated with the alert.</param>
            /// <param name="destinationIp">The destination IP address associated with the alert.</param>
            /// <param name="assignedTo">The user or team assigned to investigate the alert.</param>
            /// <param name="timestamp">The date and time when the alert was generated.</param>
            /// <param name="status">The current status of the alert (e.g., New, In Progress, Resolved).</param>
            /// <returns>true if the alert was successfully created; otherwise, false.</returns>
        public static bool Insert(int logId, string message, string attackType, string severity, string sourceIp, string destinationIp, string assignedTo, DateTime timestamp, string status)
        {
            return DAL.AlertDal.Insert(logId, message, attackType, severity, sourceIp, destinationIp, assignedTo, timestamp, status);
        }

        /// <summary>
            /// Updates an existing alert with new information.
            /// </summary>
            /// <param name="alertId">The AlertID of the alert to update.</param>
            /// <param name="logId">The new associated LogID.</param>
            /// <param name="message">The updated alert message.</param>
            /// <param name="attackType">The updated attack type.</param>
            /// <param name="severity">The updated severity level.</param>
            /// <param name="sourceIp">The updated source IP address.</param>
            /// <param name="destinationIp">The updated destination IP address.</param>
            /// <param name="assignedTo">The updated assignee.</param>
            /// <param name="timestamp">The updated timestamp.</param>
            /// <param name="status">The updated status.</param>
            /// <returns>true if the alert was successfully updated; otherwise, false.</returns>
        public static bool Update(int alertId, int logId, string message, string attackType, string severity, string sourceIp, string destinationIp, string assignedTo, DateTime timestamp, string status)
        {
            return DAL.AlertDal.Update(alertId, logId, message, attackType, severity, sourceIp, destinationIp, assignedTo, timestamp, status);
        }

        /// <summary>
            /// Deletes a specific alert from the system.
            /// </summary>
            /// <param name="alertId">The AlertID of the alert to delete.</param>
            /// <returns>true if the alert was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int alertId)
        {
            return DAL.AlertDal.Delete(alertId);
        }

        /// <summary>
            /// Retrieves all alerts associated with a specific log entry.
            /// </summary>
            /// <param name="logId">The LogID to search for associated alerts.</param>
            /// <returns>A collection of Alert objects associated with the specified log entry.</returns>
        internal static AlertCollection GetByLogId(int logId)
        {
            return DAL.AlertDal.GetByLogId(logId);
        }
    }
}