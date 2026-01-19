using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a security signature used for intrusion detection.
    /// Contains information about attack patterns, network traffic characteristics,
    /// and detection rules.
    /// </summary>
    public class Signatures
    {
        int signatureId;
        string engine;
        string ruleText;
        string protocol;
        string srcIp;
        string srcPort;
        string direction;
        string destIp;
        string destPort;
        string flow;
        string http;
        string tls;
        string contentPattern;
        double sid;
        int? rev;
        DateTime created_at;
        string attackName;
        string severity;

        /// <summary>Gets or sets the unique identifier for the signature.</summary>
        public int SignatureId { get => signatureId; set => signatureId = value; }

        /// <summary>Gets or sets the name of the attack detected by this signature.</summary>
        public string AttackName { get => attackName; set => attackName = value; }

        /// <summary>Gets or sets the detection engine that uses this signature.</summary>
        public string Engine { get => engine; set => engine = value; }

        /// <summary>Gets or sets the rule text or detection pattern.</summary>
        public string RuleText { get => ruleText; set => ruleText = value; }

        /// <summary>Gets or sets the network protocol (TCP, UDP, etc.).</summary>
        public string Protocol { get => protocol; set => protocol = value; }

        /// <summary>Gets or sets the source IP address.</summary>
        public string SrcIp { get => srcIp; set => srcIp = value; }

        /// <summary>Gets or sets the source port number.</summary>
        public string SrcPort { get => srcPort; set => srcPort = value; }

        /// <summary>Gets or sets the traffic direction (inbound, outbound, etc.).</summary>
        public string Direction { get => direction; set => direction = value; }

        /// <summary>Gets or sets the destination IP address.</summary>
        public string DestIp { get => destIp; set => destIp = value; }

        /// <summary>Gets or sets the flow characteristics of the network traffic.</summary>
        public string Flow { get => flow; set => flow = value; }

        /// <summary>Gets or sets HTTP-specific detection patterns.</summary>
        public string Http { get => http; set => http = value; }

        /// <summary>Gets or sets TLS/SSL-related detection patterns.</summary>
        public string Tls { get => tls; set => tls = value; }

        /// <summary>Gets or sets content patterns used for payload inspection.</summary>
        public string ContentPattern { get => contentPattern; set => contentPattern = value; }

        /// <summary>Gets or sets the signature ID (SID).</summary>
        public double Sid { get => sid; set => sid = value; }

        /// <summary>Gets or sets the revision number of the signature.</summary>
        public int? Rev { get => rev; set => rev = value; }

        /// <summary>Gets or sets the timestamp when the signature was created.</summary>
        public DateTime Created_at { get => created_at; set => created_at = value; }

        /// <summary>Gets or sets the destination port number.</summary>
        public string DestPort { get => destPort; set => destPort = value; }

        /// <summary>Gets or sets the severity level of the detected attack.</summary>
        public string Severity { get => severity; set => severity = value; }

        /// <summary>
        /// Initializes a new instance of the Signatures class with default values.
        /// </summary>
        internal Signatures()
        {
            this.signatureId = 0;
            this.attackName = "";
            this.engine = "";
            this.ruleText = "";
            this.http = "";
            this.flow = "";
            this.tls = "";
            this.srcIp = "";
            this.srcPort = "";
            this.destIp = "";
            this.destPort = "";
            this.contentPattern = "";
            this.sid = 0;
            this.rev = 0;
            this.created_at = DateTime.Now;
            this.protocol = "";
            this.direction = "";
            this.severity = "";
        }

        /// <summary>
        /// Initializes a new instance of the Signatures class with specified parameters.
        /// </summary>
        /// <param name="signatureId">The unique identifier for the signature.</param>
        /// <param name="attackName">The name of the attack detected by this signature.</param>
        /// <param name="engine">The detection engine that uses this signature.</param>
        /// <param name="ruleText">The rule text or detection pattern.</param>
        /// <param name="protocol">The network protocol (TCP, UDP, etc.).</param>
        /// <param name="srcIp">The source IP address.</param>
        /// <param name="srcPort">The source port number.</param>
        /// <param name="direction">The traffic direction.</param>
        /// <param name="destIp">The destination IP address.</param>
        /// <param name="destPort">The destination port number.</param>
        /// <param name="flow">The flow characteristics of the network traffic.</param>
        /// <param name="http">HTTP-specific detection patterns.</param>
        /// <param name="tls">TLS/SSL-related detection patterns.</param>
        /// <param name="contentPattern">Content patterns used for payload inspection.</param>
        /// <param name="sid">The signature ID (SID).</param>
        /// <param name="rev">The revision number of the signature.</param>
        /// <param name="created_at">The timestamp when the signature was created.</param>
        /// <param name="severity">The severity level of the detected attack.</param>
        internal Signatures(int signatureId, string attackName, string engine, string ruleText, string protocol, string srcIp, string srcPort, string direction, string destIp, string destPort, string flow, string http, string tls, string contentPattern, double sid, int? rev, DateTime created_at, string severity)
        {
            this.signatureId = signatureId;
            this.attackName = attackName;
            this.engine = engine;
            this.ruleText = ruleText;
            this.http = http;
            this.flow = flow;
            this.tls = tls;
            this.srcIp = srcIp;
            this.srcPort = srcPort;
            this.destIp = destIp;
            this.destPort = destPort;
            this.contentPattern = contentPattern;
            this.sid = sid;
            this.rev = rev;
            this.created_at = created_at;
            this.protocol = protocol;
            this.direction = direction;
            this.severity = severity;
        }

        /// <summary>
        /// Initializes a new instance of the Signatures class as a copy of the specified Signatures object.
        /// </summary>
        /// <param name="sign">The Signatures object to copy.</param>
        internal Signatures(Signatures sign) : this(sign.signatureId, sign.attackName, sign.engine, sign.ruleText, sign.protocol, sign.srcIp, sign.srcPort, sign.direction, sign.destIp, sign.destPort, sign.flow, sign.http, sign.tls, sign.contentPattern, sign.sid, sign.rev, sign.created_at, sign.severity)
        {
        }

        /// <summary>
        /// Creates a new object that is a copy of the current instance.
        /// </summary>
        /// <returns>A new Signatures object that is a copy of this instance.</returns>
        public Signatures Clone()
        {
            return new Signatures(this);
        }
    }
}