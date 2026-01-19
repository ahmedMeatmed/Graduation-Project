using IDSApp.Collection;
using IDSApp.DAL;
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
    /// Provides business logic layer operations for intrusion detection signature management.
    /// This class serves as a facade to the data access layer, providing a clean API for signature-related operations.
    /// </summary>
    internal class SignatureBLL
    {
        /// <summary>
        /// Retrieves all intrusion detection signatures from the system.
        /// </summary>
        /// <returns>A collection of Signatures objects containing all detection rules in the system.</returns>
        public static SignatureCollection GetAll()
        {
            return DAL.SignatureDal.GetAll();
        }

        /// <summary>
        /// Creates a new intrusion detection signature in the system.
        /// </summary>
        /// <param name="attackName">The name of the attack or threat this signature detects.</param>
        /// <param name="engine">The detection engine this signature is designed for (e.g., Snort, Suricata, YARA).</param>
        /// <param name="ruleText">The complete rule text or pattern for the detection signature.</param>
        /// <param name="protocol">The network protocol this signature monitors (e.g., TCP, UDP, HTTP, DNS).</param>
        /// <param name="srcIp">The source IP address pattern or condition for matching.</param>
        /// <param name="srcPort">The source port pattern or condition for matching.</param>
        /// <param name="direction">The traffic direction this signature monitors (e.g., -&gt;, &lt;&gt;, any).</param>
        /// <param name="destIp">The destination IP address pattern or condition for matching.</param>
        /// <param name="destPort">The destination port pattern or condition for matching.</param>
        /// <param name="flow">The flow conditions for session tracking and stateful inspection.</param>
        /// <param name="http">HTTP-specific inspection parameters and conditions.</param>
        /// <param name="tls">TLS/SSL-specific inspection parameters and conditions.</param>
        /// <param name="contentPattern">The content pattern or regular expression for payload inspection.</param>
        /// <param name="sid">The signature identifier number (unique for each rule).</param>
        /// <param name="rev">The revision number of the signature.</param>
        /// <param name="severity">The severity level of the detected threat (e.g., High, Medium, Low).</param>
        /// <param name="created_at">The date and time when the signature was created.</param>
        /// <returns>true if the signature was successfully created; otherwise, false.</returns>
        public static bool Insert(
       string attackName, string engine, string ruleText, string protocol,
       string srcIp, string srcPort, string direction, string destIp, string destPort,
       string flow, string http, string tls, string contentPattern, double sid, int rev, string severity, DateTime created_at)
        {
            return DAL.SignatureDal.Insert(attackName, engine, ruleText, protocol, srcIp, srcPort, direction, destIp, destPort, flow, http, tls, contentPattern, sid, rev, severity, created_at);
        }

        /// <summary>
        /// Retrieves the attack name associated with a specific signature identifier.
        /// </summary>
        /// <param name="signatureId">The SignatureID to look up.</param>
        /// <returns>The name of the attack detected by the specified signature.</returns>
        public static string GetAttackNameBySignatureId(int signatureId)
        {
            return SignatureDal.GetAttackNameBySignatureId(signatureId);
        }

        /// <summary>
        /// Updates an existing intrusion detection signature with new information.
        /// </summary>
        /// <param name="signatureId">The SignatureID of the signature to update.</param>
        /// <param name="attackName">The updated attack name.</param>
        /// <param name="engine">The updated detection engine.</param>
        /// <param name="ruleText">The updated rule text.</param>
        /// <param name="protocol">The updated protocol.</param>
        /// <param name="srcIp">The updated source IP pattern.</param>
        /// <param name="srcPort">The updated source port pattern.</param>
        /// <param name="direction">The updated traffic direction.</param>
        /// <param name="destIp">The updated destination IP pattern.</param>
        /// <param name="destPort">The updated destination port pattern.</param>
        /// <param name="flow">The updated flow conditions.</param>
        /// <param name="http">The updated HTTP inspection parameters.</param>
        /// <param name="tls">The updated TLS inspection parameters.</param>
        /// <param name="contentPattern">The updated content pattern.</param>
        /// <param name="sid">The updated signature identifier.</param>
        /// <param name="rev">The updated revision number.</param>
        /// <param name="severity">The updated severity level.</param>
        /// <param name="created_at">The updated creation timestamp.</param>
        /// <returns>true if the signature was successfully updated; otherwise, false.</returns>
        public static bool Update(
     int signatureId, string attackName, string engine, string ruleText, string protocol,
     string srcIp, string srcPort, string direction, string destIp, string destPort,
     string flow, string http, string tls, string contentPattern, double sid, int rev, string severity, DateTime created_at)
        {
            return DAL.SignatureDal.Update(signatureId, attackName, engine, ruleText, protocol, srcIp, srcPort, direction, destIp, destPort, flow, http, tls, contentPattern, sid, rev, severity, created_at);
        }

        /// <summary>
        /// Deletes a specific signature from the system.
        /// </summary>
        /// <param name="signatureId">The SignatureID of the signature to delete.</param>
        /// <returns>true if the signature was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int signatureId)
        {
            return DAL.SignatureDal.Delete(signatureId);
        }

        /// <summary>
        /// Retrieves a specific signature by its unique identifier.
        /// </summary>
        /// <param name="signatureId">The SignatureID of the signature to retrieve.</param>
        /// <returns>A Signatures object if found; otherwise, null.</returns>
        public static Signatures GetBySignatureId(int signatureId)
        {
            return DAL.SignatureDal.GetBySignatureId(signatureId);
        }

        /// <summary>
        /// Retrieves a signature by the attack name it detects.
        /// </summary>
        /// <param name="attackName">The name of the attack to search for.</param>
        /// <returns>A Signatures object if found; otherwise, null.</returns>
        public static Signatures GetByAttackName(string attackName)
        {
            return DAL.SignatureDal.GetByAttackName(attackName);
        }

        /// <summary>
        /// Retrieves all Snort-based detection rules from the system.
        /// </summary>
        /// <returns>A collection of Signatures objects containing Snort rules.</returns>
        public static SignatureCollection GetSnortRules()
        {
            return SignatureDal.GetSnortRules();
        }

        /// <summary>
        /// Retrieves all Suricata-based detection rules from the system.
        /// </summary>
        /// <returns>A collection of Signatures objects containing Suricata rules.</returns>
        public static SignatureCollection GetSuricataRules()
        {
            return SignatureDal.GetSuricataRules();
        }

        /// <summary>
        /// Retrieves all Emerging Threats rules from the system.
        /// </summary>
        /// <returns>A collection of Signatures objects containing Emerging Threats rules.</returns>
        public static SignatureCollection GetEmergingThreatsRules()
        {
            return SignatureDal.GetEmergingThreatsRules();
        }

        /// <summary>
        /// Retrieves all YARA-based detection rules from the system.
        /// </summary>
        /// <returns>A collection of Signatures objects containing YARA rules.</returns>
        public static SignatureCollection GetYaraRules()
        {
            return SignatureDal.GetYaraRules();
        }

        /// <summary>
        /// Retrieves the severity level of a signature that matched a specific log entry.
        /// </summary>
        /// <param name="logId">The LogID of the log entry to check.</param>
        /// <returns>The severity level of the matched signature.</returns>
        public static string GetSeverityByLogId(int logId)
        {
            return SignatureDal.GetSeverityByLogId(logId);
        }

        /// <summary>
        /// Retrieves a curated list of essential detection rules for core security monitoring.
        /// </summary>
        /// <returns>A list of Signatures objects containing essential detection rules.</returns>
        internal static List<Signatures> GetEssentialRules()
        {
            return SignatureDal.GetEssentialRules();
        }
    }
}