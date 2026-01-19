using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for DNS (Domain Name System) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for DNS log-related operations.
    /// </summary>
    internal class DnsLogBLL
    {
        /// <summary>
        /// Retrieves all DNS logs from the system.
        /// </summary>
        /// <returns>A collection of DnsLog objects containing all DNS logs in the system.</returns>
        public static DnsLogCollection GetAll()
        {
            return DnsLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific DNS log by its unique identifier.
        /// </summary>
        /// <param name="id">The DnsLogID of the DNS log to retrieve.</param>
        /// <returns>A DnsLog object if found; otherwise, null.</returns>
        public static DnsLog GetById(int id)
        {
            return DnsLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new DNS log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="query">The DNS query (domain name) that was requested.</param>
        /// <param name="queryType">The type of DNS query (e.g., A, AAAA, CNAME, MX, TXT, NS).</param>
        /// <param name="response">The DNS server's response to the query.</param>
        /// <returns>The newly created DnsLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string query, string queryType, string response,int ttl,string recordType)
        {
            return DnsLogDal.Insert(logId, query, queryType, response,ttl,recordType);
        }

        /// <summary>
        /// Deletes a specific DNS log from the system.
        /// </summary>
        /// <param name="dnsLogId">The DnsLogID of the DNS log to delete.</param>
        /// <returns>true if the DNS log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int dnsLogId)
        {
            return DnsLogDal.Delete(dnsLogId);
        }

        /// <summary>
        /// Updates an existing DNS log entry with new information.
        /// </summary>
        /// <param name="dnsLogId">The DnsLogID of the DNS log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="query">The updated DNS query.</param>
        /// <param name="queryType">The updated DNS query type.</param>
        /// <param name="response">The updated DNS response.</param>
        /// <returns>true if the DNS log was successfully updated; otherwise, false.</returns>
        public static bool Update(int dnsLogId, int logId, string query, string queryType, string response,int ttl,string recordType)
        {
            return DnsLogDal.Update(dnsLogId, logId, query, queryType, response,ttl,recordType);
        }
    }
}