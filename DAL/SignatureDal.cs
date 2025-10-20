using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling intrusion detection signature-related operations
    /// </summary>
    internal class SignatureDal
    {
        /// <summary>
        /// Retrieves all signatures from the database
        /// </summary>
        /// <returns>A SignatureCollection containing all detection signatures</returns>
        public static SignatureCollection GetAll()
        {
            SignatureCollection signatureList = new SignatureCollection();

            try
            {
                string query = "SELECT * FROM Signatures";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    Signatures signature = new Signatures(
                        (int)row["signId"],
                        row["attackName"].ToString(),
                        row["engine"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToDouble(row["sid"]),
                       row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                        (DateTime)row["created_at"],
                                                row["Severity"].ToString()

                    );
                    signatureList.Add(signature);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching all signatures: " + ex.Message);
            }

            return signatureList;
        }

        /// <summary>
        /// Inserts a new detection signature into the database
        /// </summary>
        /// <param name="attackName">The name of the attack or threat being detected</param>
        /// <param name="engine">The detection engine (e.g., Snort, Suricata, YARA, Emerging Threats)</param>
        /// <param name="ruleText">The complete rule text in the engine's syntax</param>
        /// <param name="protocol">The network protocol this rule applies to (e.g., TCP, UDP, HTTP)</param>
        /// <param name="srcIp">The source IP address pattern or range</param>
        /// <param name="srcPort">The source port pattern or range</param>
        /// <param name="direction">The traffic direction (e.g., -&gt;, &lt;&gt;)</param>
        /// <param name="destIp">The destination IP address pattern or range</param>
        /// <param name="destPort">The destination port pattern or range</param>
        /// <param name="flow">The flow characteristics for session tracking</param>
        /// <param name="http">HTTP-specific detection patterns</param>
        /// <param name="tls">TLS/SSL-specific detection patterns</param>
        /// <param name="contentPattern">The content pattern to match in packet payloads</param>
        /// <param name="sid">The signature identifier number</param>
        /// <param name="rev">The revision number of the signature</param>
        /// <param name="severity">The severity level (e.g., High, Medium, Low, Critical)</param>
        /// <param name="created_at">The timestamp when the signature was created</param>
        /// <returns>True if the insertion was successful, otherwise false</returns>
        public static bool Insert(
      string attackName, string engine, string ruleText, string protocol,
      string srcIp, string srcPort, string direction, string destIp, string destPort,
      string flow, string http, string tls, string contentPattern, double sid, int rev, string severity, DateTime created_at)
        {
            try
            {
                string query = @"INSERT INTO Signatures 
                        (attackName, engine, ruleText, protocol, srcIp, srcPort, direction, 
                         destIp, destPort, flow, http, tls, contentPattern, sid, rev,severity,Created_at) 
                        VALUES 
                        (@AttackName, @Engine, @RuleText, @Protocol, @SrcIp, @SrcPort, @Direction, 
                         @DestIp, @DestPort, @Flow, @Http, @Tls, @ContentPattern, @Sid, @Rev,@Severity,@Created_at)";

                SqlParameter[] parameters = new SqlParameter[]
                {
            new SqlParameter("@AttackName", SqlDbType.NVarChar, 255) { Value = attackName },
            new SqlParameter("@Engine", SqlDbType.NVarChar, 50) { Value = engine },
            new SqlParameter("@RuleText", SqlDbType.NVarChar, -1) { Value = ruleText }, // -1 for NVARCHAR(MAX)
            new SqlParameter("@Protocol", SqlDbType.NVarChar, 50) { Value = protocol },
            new SqlParameter("@SrcIp", SqlDbType.NVarChar, 50) { Value = srcIp },
            new SqlParameter("@SrcPort", SqlDbType.NVarChar, 50) { Value = srcPort },
            new SqlParameter("@Direction", SqlDbType.NVarChar, 5) { Value = direction },
            new SqlParameter("@DestIp", SqlDbType.NVarChar, 50) { Value = destIp },
            new SqlParameter("@DestPort", SqlDbType.NVarChar, 50) { Value = destPort },
            new SqlParameter("@Flow", SqlDbType.NVarChar, 255) { Value = flow },
            new SqlParameter("@Http", SqlDbType.NVarChar, 255) { Value = http },
            new SqlParameter("@Tls", SqlDbType.NVarChar, 255) { Value = tls },
            new SqlParameter("@ContentPattern", SqlDbType.NVarChar, -1) { Value = contentPattern }, // -1 for NVARCHAR(MAX)
            new SqlParameter("@Sid", SqlDbType.Float) { Value = sid },
            new SqlParameter("@Rev", SqlDbType.Int) { Value = rev },
            new SqlParameter("@Created_at", SqlDbType.DateTime) { Value = created_at },
new SqlParameter("@Severity", SqlDbType.NChar) { Value = severity },

                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting signature: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing detection signature in the database
        /// </summary>
        /// <param name="signatureId">The unique identifier of the signature to update</param>
        /// <param name="attackName">The updated attack name</param>
        /// <param name="engine">The updated detection engine</param>
        /// <param name="ruleText">The updated rule text</param>
        /// <param name="protocol">The updated protocol</param>
        /// <param name="srcIp">The updated source IP pattern</param>
        /// <param name="srcPort">The updated source port</param>
        /// <param name="direction">The updated traffic direction</param>
        /// <param name="destIp">The updated destination IP pattern</param>
        /// <param name="destPort">The updated destination port</param>
        /// <param name="flow">The updated flow characteristics</param>
        /// <param name="http">The updated HTTP patterns</param>
        /// <param name="tls">The updated TLS patterns</param>
        /// <param name="contentPattern">The updated content pattern</param>
        /// <param name="sid">The updated signature identifier</param>
        /// <param name="rev">The updated revision number</param>
        /// <param name="severity">The updated severity level</param>
        /// <param name="created_at">The updated creation timestamp</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(
       int signatureId, string attackName, string engine, string ruleText, string protocol,
       string srcIp, string srcPort, string direction, string destIp, string destPort,
       string flow, string http, string tls, string contentPattern, double sid, int rev, string severity, DateTime created_at)
        {
            try
            {
                string query = @"UPDATE Signatures 
                        SET attackName = @AttackName, engine = @Engine, ruleText = @RuleText, 
                            protocol = @Protocol, srcIp = @SrcIp, srcPort = @SrcPort, 
                            direction = @Direction, destIp = @DestIp, destPort = @DestPort, 
                            flow = @Flow, http = @Http, tls = @Tls, 
                            contentPattern = @ContentPattern, sid = @Sid, rev = @Rev,@Severity=severity,@Created_at=created_at
                        WHERE SignatureID = @SignatureID";

                SqlParameter[] parameters = new SqlParameter[]
                {
            new SqlParameter("@SignatureID", SqlDbType.Int) { Value = signatureId },
            new SqlParameter("@AttackName", SqlDbType.NVarChar, 255) { Value = attackName },
            new SqlParameter("@Engine", SqlDbType.NVarChar, 50) { Value = engine },
            new SqlParameter("@RuleText", SqlDbType.NVarChar, -1) { Value = ruleText }, // NVARCHAR(MAX)
            new SqlParameter("@Protocol", SqlDbType.NVarChar, 50) { Value = protocol },
            new SqlParameter("@SrcIp", SqlDbType.NVarChar, 50) { Value = srcIp },
            new SqlParameter("@SrcPort", SqlDbType.NVarChar, 50) { Value = srcPort },
            new SqlParameter("@Direction", SqlDbType.NVarChar, 5) { Value = direction },
            new SqlParameter("@DestIp", SqlDbType.NVarChar, 50) { Value = destIp },
            new SqlParameter("@DestPort", SqlDbType.NVarChar, 50) { Value = destPort },
            new SqlParameter("@Flow", SqlDbType.NVarChar, 255) { Value = flow },
            new SqlParameter("@Http", SqlDbType.NVarChar, 255) { Value = http },
            new SqlParameter("@Tls", SqlDbType.NVarChar, 255) { Value = tls },
            new SqlParameter("@ContentPattern", SqlDbType.NVarChar, -1) { Value = contentPattern }, // NVARCHAR(MAX)
            new SqlParameter("@Sid", SqlDbType.Float) { Value = sid },
            new SqlParameter("@Rev", SqlDbType.Int) { Value = rev },
            new SqlParameter("@Created_at", SqlDbType.DateTime) { Value = created_at },
            new SqlParameter("@Severity", SqlDbType.NChar) { Value = severity },
                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating signature: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a signature from the database
        /// </summary>
        /// <param name="signatureId">The unique identifier of the signature to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int signatureId)
        {
            try
            {
                string query = "DELETE FROM Signatures WHERE SignatureID = @SignatureID";
                SqlParameter[] parameters = new SqlParameter[]
                {
                    new SqlParameter("@SignatureID", SqlDbType.Int) { Value = signatureId }
                };

                return DBL.DBL.ExecuteNonQueryWithParameters(query, parameters) > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting signature: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a specific signature by its unique identifier
        /// </summary>
        /// <param name="signatureId">The signId of the signature to retrieve</param>
        /// <returns>A Signatures object if found, otherwise null</returns>
        public static Signatures GetBySignatureId(int signatureId)
        {
            Signatures signature = null;

            try
            {
                string query = "SELECT * FROM Signatures WHERE signId = @SignId";
                SqlParameter[] parameters = new SqlParameter[]
                {
            new SqlParameter("@SignId", SqlDbType.Int) { Value = signatureId }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];

                    signature = new Signatures(
                        (int)row["signId"],
                        row["engine"].ToString(),
                        row["attackName"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToInt32(row["sid"]),
                        Convert.ToInt32(row["rev"]),
                        Convert.ToDateTime(row["created_at"]),
                        row["Severity"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching signature by SignatureID: " + ex.Message);
            }

            return signature;
        }

        /// <summary>
        /// Retrieves a signature by its attack name
        /// </summary>
        /// <param name="attackName">The attack name to search for</param>
        /// <returns>A Signatures object if found, otherwise null</returns>
        public static Signatures GetByAttackName(string attackName)
        {
            Signatures signature = null;

            try
            {
                string query = "SELECT * FROM Signatures WHERE attackName = @AttackName";
                SqlParameter[] parameters = new SqlParameter[]
                {
            new SqlParameter("@AttackName", SqlDbType.NVarChar, 255) { Value = attackName }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];

                    signature = new Signatures(
                        (int)row["signId"],
                        row["engine"].ToString(),
                        row["attackName"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToInt32(row["sid"]),
                        Convert.ToInt32(row["rev"]),
                        Convert.ToDateTime(row["created_at"]),
                        row["Severity"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching signature by AttackName: " + ex.Message);
            }

            return signature;
        }

        /// <summary>
        /// Gets the attack name for a specific signature ID using caching for performance
        /// </summary>
        /// <param name="signatureId">The signature identifier</param>
        /// <returns>The attack name if found, otherwise "Unknown"</returns>
        private static readonly ConcurrentDictionary<int, string> _attackNameCache = new ConcurrentDictionary<int, string>();

        public static string GetAttackNameBySignatureId(int signatureId)
        {
            // Check cache first
            if (_attackNameCache.TryGetValue(signatureId, out string attackName))
                return attackName;

            try
            {
                // Query database
                string query = "SELECT AttackName FROM Signatures WHERE SignatureId = @SignatureId";
                SqlParameter[] parameters = { new SqlParameter("@SignatureId", SqlDbType.Int) { Value = signatureId } };
                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                attackName = result?.ToString() ?? "Unknown";

                // Cache the result
                _attackNameCache[signatureId] = attackName;
                return attackName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching attack name for SignatureId {signatureId}: {ex.Message}");
                return "Unknown";
            }
        }

        /// <summary>
        /// Retrieves all Snort detection rules from the database
        /// </summary>
        /// <returns>A SignatureCollection containing Snort rules</returns>
        public static SignatureCollection GetSnortRules()
        {
            SignatureCollection signatureList = new SignatureCollection();
            try
            {
                string query = "SELECT  * FROM Signatures WHERE engine = 'Emerging Threats'";
                DataTable dt = DBL.DBL.ExecuteQuery(query);
                foreach (DataRow row in dt.Rows)
                {
                    Signatures signature = new Signatures(
                        (int)row["signId"],
                        row["attackName"].ToString(),
                        row["engine"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToDouble(row["sid"]),
                        row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                        (DateTime)row["created_at"],
                        row["Severity"].ToString()
                    );
                    signatureList.Add(signature);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Snort rules: " + ex.Message);
            }
            return signatureList;
        }

        /// <summary>
        /// Retrieves all Suricata detection rules from the database
        /// </summary>
        /// <returns>A SignatureCollection containing Suricata rules</returns>
        public static SignatureCollection GetSuricataRules()
        {
            SignatureCollection signatureList = new SignatureCollection();
            try
            {
                string query = "SELECT   * FROM Signatures WHERE engine = 'suricata'";
                DataTable dt = DBL.DBL.ExecuteQuery(query);
                foreach (DataRow row in dt.Rows)
                {
                    Signatures signature = new Signatures(
                        (int)row["signId"],
                        row["attackName"].ToString(),
                        row["engine"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToDouble(row["sid"]),
                        row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                        (DateTime)row["created_at"],
                        row["Severity"].ToString()

                    );
                    signatureList.Add(signature);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Suricata rules: " + ex.Message);
            }
            return signatureList;
        }

        /// <summary>
        /// Retrieves all Emerging Threats detection rules from the database
        /// </summary>
        /// <returns>A SignatureCollection containing Emerging Threats rules</returns>
        public static SignatureCollection GetEmergingThreatsRules()
        {
            SignatureCollection signatureList = new SignatureCollection();
            try
            {
                string query = "SELECT   *FROM Signatures WHERE engine = 'Emerging Threats'";
                DataTable dt = DBL.DBL.ExecuteQuery(query);
                foreach (DataRow row in dt.Rows)
                {
                    Signatures signature = new Signatures(
                        (int)row["signId"],
                        row["attackName"].ToString(),
                        row["engine"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToDouble(row["sid"]),
                        row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                        (DateTime)row["created_at"],
                         row["Severity"].ToString()

                    );
                    signatureList.Add(signature);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Emerging Threats rules: " + ex.Message);
            }
            return signatureList;
        }

        /// <summary>
        /// Retrieves all YARA detection rules from the database
        /// </summary>
        /// <returns>A SignatureCollection containing YARA rules</returns>
        public static SignatureCollection GetYaraRules()
        {
            SignatureCollection signatureList = new SignatureCollection();
            try
            {
                string query = "SELECT    * FROM Signatures WHERE engine = 'yara'";
                DataTable dt = DBL.DBL.ExecuteQuery(query);
                foreach (DataRow row in dt.Rows)
                {
                    Signatures signature = new Signatures(
                        (int)row["signId"],
                        row["attackName"].ToString(),
                        row["engine"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToDouble(row["sid"]),
                        row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                        (DateTime)row["created_at"],
                                                row["Severity"].ToString()

                    );
                    signatureList.Add(signature);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Yara rules: " + ex.Message);
            }
            return signatureList;
        }

        /// <summary>
        /// Retrieves the severity level for a specific log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>The severity level if found, otherwise "Unknown" or "Error"</returns>
        public static string GetSeverityByLogId(int logId)
        {
            try
            {
                string query = "SELECT Severity FROM Signatures WHERE signId = @LogId";
                SqlParameter[] parameters =
                {
            new SqlParameter("@LogId", SqlDbType.Int) { Value = logId }
        };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);

                if (result != null && result != DBNull.Value)
                {
                    return result.ToString();
                }
                else
                {
                    return "Unknown"; // If no record found with this logId
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching Severity for logId {logId}: {ex.Message}");
                return "Error";
            }
        }

        /// <summary>
        /// Retrieves essential high-priority detection rules optimized for performance
        /// </summary>
        /// <returns>A SignatureCollection containing essential detection rules</returns>
        public static SignatureCollection GetEssentialRules()
        {
            SignatureCollection signatureList = new SignatureCollection();

            try
            {
                // Query to get high-priority rules with optimized selection criteria
                string query = @"
            SELECT TOP 2000 * FROM Signatures 
            WHERE 
                -- High severity rules first
                (Severity IN ('High', 'Critical') OR Severity IS NULL)
                -- Common attack patterns
                AND (attackName LIKE '%exploit%' OR 
                     attackName LIKE '%malware%' OR 
                     attackName LIKE '%trojan%' OR 
                     attackName LIKE '%worm%' OR 
                     attackName LIKE '%ransomware%' OR
                     attackName LIKE '%backdoor%' OR
                     attackName LIKE '%scan%' OR
                     attackName LIKE '%brute%' OR
                     attackName LIKE '%injection%' OR
                     attackName LIKE '%xss%' OR
                     attackName LIKE '%sqli%')
                -- Focus on common protocols
                AND (protocol IN ('tcp', 'udp', 'http', 'dns', 'ftp', 'ssh', 'smtp') OR protocol IS NULL)
            ORDER BY 
                -- Priority: High severity first, then by attack relevance
                CASE 
                    WHEN Severity = 'Critical' THEN 1
                    WHEN Severity = 'High' THEN 2
                    WHEN Severity = 'Medium' THEN 3
                    ELSE 4
                END,
                -- Prefer rules with content patterns (more specific detection)
                CASE WHEN contentPattern IS NOT NULL AND contentPattern != '' THEN 1 ELSE 2 END,
                -- Recent rules first
                created_at DESC";

                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    Signatures signature = new Signatures(
                        (int)row["signId"],
                        row["attackName"].ToString(),
                        row["engine"].ToString(),
                        row["ruleText"].ToString(),
                        row["protocol"].ToString(),
                        row["srcIp"].ToString(),
                        row["srcPort"].ToString(),
                        row["direction"].ToString(),
                        row["destIp"].ToString(),
                        row["destPort"].ToString(),
                        row["flow"].ToString(),
                        row["http"].ToString(),
                        row["tls"].ToString(),
                        row["contentPattern"].ToString(),
                        Convert.ToDouble(row["sid"]),
                        row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                        (DateTime)row["created_at"],
                        row["Severity"].ToString()
                    );
                    signatureList.Add(signature);
                }

                Console.WriteLine($"[SignatureDal] Loaded {signatureList.Count} essential rules");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching essential rules: " + ex.Message);

                // Fallback: get a small subset of rules
                try
                {
                    string fallbackQuery = "SELECT TOP 1000 * FROM Signatures ORDER BY created_at DESC";
                    DataTable dt = DBL.DBL.ExecuteQuery(fallbackQuery);

                    foreach (DataRow row in dt.Rows)
                    {
                        Signatures signature = new Signatures(
                            (int)row["signId"],
                            row["attackName"].ToString(),
                            row["engine"].ToString(),
                            row["ruleText"].ToString(),
                            row["protocol"].ToString(),
                            row["srcIp"].ToString(),
                            row["srcPort"].ToString(),
                            row["direction"].ToString(),
                            row["destIp"].ToString(),
                            row["destPort"].ToString(),
                            row["flow"].ToString(),
                            row["http"].ToString(),
                            row["tls"].ToString(),
                            row["contentPattern"].ToString(),
                            Convert.ToDouble(row["sid"]),
                            row["rev"] == DBNull.Value ? (int?)null : Convert.ToInt32(row["rev"]),
                            (DateTime)row["created_at"],
                            row["Severity"].ToString()
                        );
                        signatureList.Add(signature);
                    }

                    Console.WriteLine($"[SignatureDal] Fallback: Loaded {signatureList.Count} rules");
                }
                catch (Exception fallbackEx)
                {
                    Console.WriteLine("Error in fallback rule loading: " + fallbackEx.Message);
                }
            }

            return signatureList;
        }
    }
}