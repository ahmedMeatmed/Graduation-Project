using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a comprehensive network log entry captured by the Intrusion Detection System.
    /// Contains general network traffic information along with protocol-specific log details
    /// for comprehensive security monitoring and threat detection across multiple protocols.
    /// </summary>
    internal class Logs
    {
        int id;
        DateTime time;
        string srcIp;
        string destIp;
        double packetSize;
        bool isMalicious;
        AlertCollection alerts;
        string protocolName;
        string protocol;
        int srcPort;
        int destPort;
        double payloadSize;
        string tcpFlags;
        string flowDirection;
        int packetCount;
        double duration;
        int? matchedSignatureId;
        string info;

        // Protocol-specific logs
        HttpLog httpLog;
        DnsLog dnsLog;
        SmbLog smbLog;
        FtpLog ftpLog;
        SmtpLog smtpLog;
        TlsLog tlsLog;
        TelnetLog telnetLog;
        RdpLog rdpLog;
        IcmpLog icmpLog;
        SshLog sshLog;

        /// <summary>Unique identifier for the log entry</summary>
        public int Id { get => id; set => id = value; }

        /// <summary>Timestamp when the network event occurred</summary>
        public DateTime Time { get => time; set => time = value; }

        /// <summary>Source IP address of the network traffic</summary>
        public string SrcIp { get => srcIp; set => srcIp = value; }

        /// <summary>Destination IP address of the network traffic</summary>
        public string DestIp { get => destIp; set => destIp = value; }

        /// <summary>Size of the network packet in bytes</summary>
        public double PacketSize { get => packetSize; set => packetSize = value; }

        /// <summary>Indicates whether the traffic was flagged as malicious by detection rules</summary>
        public bool IsMalicious { get => isMalicious; set => isMalicious = value; }

        /// <summary>Collection of alerts generated from this log entry</summary>
        internal AlertCollection Alerts { get => alerts; set => alerts = value; }

        /// <summary>Human-readable name of the network protocol</summary>
        public string ProtocolName { get => protocolName; set => protocolName = value; }

        /// <summary>Technical protocol identifier or abbreviation</summary>
        public string Protocol { get => protocol; set => protocol = value; }

        /// <summary>Source port number of the network connection</summary>
        public int SrcPort { get => srcPort; set => srcPort = value; }

        /// <summary>Destination port number of the network connection</summary>
        public int DestPort { get => destPort; set => destPort = value; }

        /// <summary>Size of the payload data in bytes, excluding headers</summary>
        public double PayloadSize { get => payloadSize; set => payloadSize = value; }

        /// <summary>TCP flags set in the packet (e.g., SYN, ACK, FIN, RST, PSH, URG)</summary>
        public string TcpFlags { get => tcpFlags; set => tcpFlags = value; }

        /// <summary>Direction of network flow (e.g., Inbound, Outbound, Internal)</summary>
        public string FlowDirection { get => flowDirection; set => flowDirection = value; }

        /// <summary>Number of packets in the network session or capture</summary>
        public int PacketCount { get => packetCount; set => packetCount = value; }

        /// <summary>Duration of the network session in seconds</summary>
        public double Duration { get => duration; set => duration = value; }

        /// <summary>Identifier of the intrusion detection signature that matched this traffic</summary>
        public int? MatchedSignatureId { get => matchedSignatureId; set => matchedSignatureId = value; }

        /// <summary>Additional informational context about the log entry</summary>
        public string Info { get => info; set => info = value; }

        // Protocol-specific properties

        /// <summary>HTTP protocol-specific log details</summary>
        public HttpLog HttpLog { get => httpLog; set => httpLog = value; }

        /// <summary>DNS protocol-specific log details</summary>
        public DnsLog DnsLog { get => dnsLog; set => dnsLog = value; }

        /// <summary>SMB (Server Message Block) protocol-specific log details</summary>
        public SmbLog SmbLog { get => smbLog; set => smbLog = value; }

        /// <summary>FTP protocol-specific log details</summary>
        public FtpLog FtpLog { get => ftpLog; set => ftpLog = value; }

        /// <summary>SMTP protocol-specific log details</summary>
        public SmtpLog SmtpLog { get => smtpLog; set => smtpLog = value; }

        /// <summary>TLS/SSL protocol-specific log details</summary>
        public TlsLog TlsLog { get => tlsLog; set => tlsLog = value; }

        /// <summary>Telnet protocol-specific log details</summary>
        public TelnetLog TelnetLog { get => telnetLog; set => telnetLog = value; }

        /// <summary>RDP (Remote Desktop Protocol) protocol-specific log details</summary>
        public RdpLog RdpLog { get => rdpLog; set => rdpLog = value; }

        /// <summary>ICMP protocol-specific log details</summary>
        public IcmpLog IcmpLog { get => icmpLog; set => icmpLog = value; }

        /// <summary>SSH protocol-specific log details</summary>
        public SshLog SshLog { get => sshLog; set => sshLog = value; }

        /// <summary>
        /// Initializes a new instance of the Logs class with specified parameters.
        /// </summary>
        /// <param name="id">Unique identifier for the log entry</param>
        /// <param name="time">Timestamp when the network event occurred</param>
        /// <param name="srcIp">Source IP address of the network traffic</param>
        /// <param name="destIp">Destination IP address of the network traffic</param>
        /// <param name="packetSize">Size of the network packet in bytes</param>
        /// <param name="isMalicious">Whether traffic was flagged as malicious</param>
        /// <param name="alerts">Collection of alerts generated from this log</param>
        /// <param name="protocolName">Human-readable name of the network protocol</param>
        /// <param name="protocol">Technical protocol identifier</param>
        /// <param name="srcPort">Source port number</param>
        /// <param name="destPort">Destination port number</param>
        /// <param name="payloadSize">Size of payload data in bytes</param>
        /// <param name="tcpFlags">TCP flags set in the packet</param>
        /// <param name="flowDirection">Direction of network flow</param>
        /// <param name="packetCount">Number of packets in the session</param>
        /// <param name="duration">Duration of the network session in seconds</param>
        /// <param name="matchedSignatureId">ID of matched intrusion detection signature</param>
        /// <param name="info">Additional informational context</param>
        internal Logs(int id, DateTime time, string srcIp, string destIp, double packetSize, bool isMalicious,
                      AlertCollection alerts, string protocolName, string protocol, int srcPort, int destPort, double payloadSize,
                      string tcpFlags, string flowDirection, int packetCount, double duration, int? matchedSignatureId, string info)
        {
            this.id = id;
            this.time = time;
            this.srcIp = srcIp;
            this.destIp = destIp;
            this.packetSize = packetSize;
            this.isMalicious = isMalicious;
            this.alerts = alerts;
            this.protocolName = protocolName;
            this.protocol = protocol;
            this.srcPort = srcPort;
            this.destPort = destPort;
            this.payloadSize = payloadSize;
            this.tcpFlags = tcpFlags;
            this.flowDirection = flowDirection;
            this.packetCount = packetCount;
            this.duration = duration;
            this.matchedSignatureId = matchedSignatureId;
            this.info = info;
        }

        /// <summary>
        /// Initializes a new instance of the Logs class as a copy of an existing Logs object.
        /// Includes copying of all protocol-specific log objects.
        /// </summary>
        /// <param name="l">Source Logs object to copy from</param>
        internal Logs(Logs l)
            : this(l.id, l.time, l.srcIp, l.destIp, l.packetSize, l.isMalicious, l.alerts, l.protocolName, l.protocol,
                   l.srcPort, l.destPort, l.payloadSize, l.tcpFlags, l.flowDirection, l.packetCount, l.duration, l.matchedSignatureId, l.info)
        {
            this.httpLog = l.httpLog;
            this.dnsLog = l.dnsLog;
            this.smbLog = l.smbLog;
            this.ftpLog = l.ftpLog;
            this.smtpLog = l.smtpLog;
            this.tlsLog = l.tlsLog;
            this.telnetLog = l.telnetLog;
            this.rdpLog = l.rdpLog;
            this.icmpLog = l.icmpLog;
        }

        /// <summary>
        /// Creates a deep copy of the current Logs instance including all protocol-specific log objects.
        /// </summary>
        /// <returns>A new Logs object that is an exact copy of the current instance</returns>
        public Logs Clone()
        {
            return new Logs(this);
        }
    }
}