using IDSApp.Helper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IDSApp.ProtocolParsing
{
    public class LdapParser : IDisposable
    {
        private string _operation = "unknown";
        private string _dn = "none";
        private string _filter = "none";
        private int _messageId = -1;
        private int _resultCode = -1;
        private string _status = "unknown";
        private Dictionary<string, string> _attributes = new();
        private bool _isSuspicious = false;
        private string _parseError = "";
        private byte[] _originalData;

        public LdapParser() { }

        public LdapParseResult Parse(byte[] payload)
        {
            ResetState();
            _originalData = payload;

            var result = new LdapParseResult();

            try
            {
                if (payload == null || payload.Length == 0)
                {
                    _parseError = "Empty payload";
                    result.Operation = "empty";
                    return result;
                }

                byte firstByte = payload[0];
                OptimizedLogger.LogImportant($"[LDAP-PARSE] Starting parse, payload length: {payload.Length}");
                OptimizedLogger.LogImportant($"[LDAP-PARSE] First byte: 0x{firstByte:X2}");
                OptimizedLogger.LogImportant($"[LDAP-PARSE] First 16 bytes: {BitConverter.ToString(payload, 0, Math.Min(16, payload.Length))}");

                // **الحل الجديد: اعترف بالأنواع المختلفة وعالجها**
                if (firstByte != 0x30)
                {
                    // اعترف بالأنواع المختلفة وارجع operation مفيدة
                    if (firstByte == 0x00 && payload.Length >= 4)
                    {
                        return ParseDirectoryService(payload, result);
                    }
                    else if (firstByte == 0xC2)
                    {
                        _operation = "EncryptedLDAP";
                        _status = "encrypted";

                        // حاول استخراج معلومات إضافية من البيانات المشفرة
                        if (payload.Length >= 8)
                        {
                            _attributes["EncryptedSize"] = payload.Length.ToString();
                            _attributes["SecondByte"] = $"0x{payload[1]:X2}";

                            // تحقق إذا كان هذا TLS/SSL
                            if (payload[1] == 0x14 || payload[1] == 0x15 || payload[1] == 0x16 || payload[1] == 0x17)
                            {
                                _operation = "TLS_LDAP";
                                _attributes["TLS_ContentType"] = GetTlsContentType(payload[1]);
                            }
                        }

                        UpdateResultFromState(result);
                        return result;
                    }
                    else if (firstByte == 0x01)
                    {
                        _operation = "BinaryProtocol";
                        _status = "binary";
                        _parseError = "Binary Protocol Response (starts with 0x01)";
                        UpdateResultFromState(result);
                        return result;
                    }
                    else
                    {
                        // الأنواع التانية
                        _parseError = $"Not LDAP. Detected: Unknown Protocol. First byte: 0x{firstByte:X2}";
                        result.Operation = "wrong_protocol";
                        return result;
                    }
                }

                // الباقي نفس الكود الحالي للـ LDAP العادي...
                using var ms = new MemoryStream(payload);
                using var reader = new BinaryReader(ms);

                if (!ParseLdapMessage(reader, result))
                {
                    result.Operation = $"parse_error: {_parseError}";
                    return result;
                }

                DetectSuspiciousBehavior();
                UpdateResultFromState(result);

                OptimizedLogger.LogImportant($"[LDAP-PARSE] Parse completed: Operation={_operation}, MessageID={_messageId}, ResultCode={_resultCode}");
                return result;
            }
            catch (EndOfStreamException ex)
            {
                _parseError = $"End of stream: {ex.Message}";
                OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                result.Operation = "truncated";
                result.Filter = _parseError;
                return result;
            }
            catch (Exception ex)
            {
                _parseError = $"Exception: {ex.Message}";
                OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                result.Operation = "error";
                result.Filter = _parseError;
                result.Status = "error";
                return result;
            }
        }

        private LdapParseResult ParseDirectoryService(byte[] payload, LdapParseResult result)
        {
            try
            {
                var dsParser = new DirectoryServiceParser();
                var dsResult = dsParser.Parse(payload);

                _operation = $"DS_{dsResult.OperationName}";
                _status = "directory_service";

                // استخرج بيانات حقيقية من الـ Directory Service
                if (dsResult.Strings.Count > 0)
                {
                    // استخدم أول string كـ DN
                    _dn = dsResult.Strings.First();

                    // ابحث عن patterns معروفة في الـ strings
                    foreach (var str in dsResult.Strings)
                    {
                        if (str.Contains("CN=") || str.Contains("DC="))
                        {
                            _dn = str;
                            break;
                        }
                    }

                    _attributes["DS_Strings"] = string.Join("; ", dsResult.Strings.Take(5));
                }

                _attributes["DS_OperationType"] = $"0x{dsResult.OperationType:X2}";
                _attributes["DS_TotalLength"] = dsResult.TotalLength.ToString();

                UpdateResultFromState(result);
                return result;
            }
            catch (Exception ex)
            {
                _operation = "DirectoryService";
                _status = "directory_service";
                _attributes["DSParseError"] = ex.Message;
                UpdateResultFromState(result);
                return result;
            }
        }

        private string GetTlsContentType(byte contentType)
        {
            return contentType switch
            {
                0x14 => "ChangeCipherSpec",
                0x15 => "Alert",
                0x16 => "Handshake",
                0x17 => "ApplicationData",
                _ => $"Unknown(0x{contentType:X2})"
            };
        }

        private bool ParseLdapMessage(BinaryReader reader, LdapParseResult result)
        {
            try
            {
                // We already checked the sequence tag, so just read it
                byte sequenceTag = reader.ReadByte(); // This should be 0x30

                int messageLength = ReadLength(reader);
                OptimizedLogger.LogImportant($"[LDAP-PARSE] Message length: {messageLength}, remaining: {reader.BaseStream.Length - reader.BaseStream.Position}");

                // **إصلاح أخطاء الطول**
                if (messageLength <= 0 || messageLength > (reader.BaseStream.Length - reader.BaseStream.Position + 1000))
                {
                    OptimizedLogger.LogImportant($"[LDAP-PARSE] Adjusting message length from {messageLength} to {reader.BaseStream.Length - reader.BaseStream.Position}");
                    messageLength = (int)(reader.BaseStream.Length - reader.BaseStream.Position);
                }

                if (messageLength <= 0 || messageLength > (reader.BaseStream.Length - reader.BaseStream.Position))
                {
                    _parseError = $"Invalid message length: {messageLength}";
                    OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                    return false;
                }

                // Parse message ID
                _messageId = ReadASN1Integer(reader);
                if (_messageId == -1)
                {
                    _parseError = "Failed to read message ID";
                    OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                    return false;
                }

                OptimizedLogger.LogImportant($"[LDAP-PARSE] Message ID: {_messageId}");

                if (reader.BaseStream.Position >= reader.BaseStream.Length)
                {
                    _parseError = "No operation tag after message ID";
                    OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                    return false;
                }

                // Parse operation
                byte opTag = reader.ReadByte();
                OptimizedLogger.LogImportant($"[LDAP-PARSE] Operation tag: 0x{opTag:X2}");

                return ParseOperation(reader, opTag);
            }
            catch (Exception ex)
            {
                _parseError = $"Message parsing failed: {ex.Message}";
                OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                return false;
            }
        }

        // باقي الـ ASN.1 Helper Methods تبقى كما هي...
        private static int ReadLength(BinaryReader reader)
        {
            if (reader.BaseStream.Position >= reader.BaseStream.Length)
                return 0;

            byte first = reader.ReadByte();
            if ((first & 0x80) == 0)
                return first;

            int numBytes = first & 0x7F;
            if (numBytes == 0)
                return -1;

            int length = 0;
            for (int i = 0; i < numBytes; i++)
            {
                if (reader.BaseStream.Position >= reader.BaseStream.Length)
                    return 0;
                length = (length << 8) | reader.ReadByte();
            }
            return length;
        }

        private static int ReadASN1Integer(BinaryReader reader)
        {
            if (reader.BaseStream.Position >= reader.BaseStream.Length)
                return 0;

            byte tag = reader.ReadByte();
            if (tag != 0x02)
            {
                SkipElement(reader);
                return 0;
            }

            int len = ReadLength(reader);
            if (len <= 0 || reader.BaseStream.Position + len > reader.BaseStream.Length)
                return 0;

            int val = 0;
            for (int i = 0; i < len; i++)
                val = (val << 8) | reader.ReadByte();

            return val;
        }

        private static bool ReadASN1Boolean(BinaryReader reader)
        {
            if (reader.BaseStream.Position >= reader.BaseStream.Length)
                return false;

            byte tag = reader.ReadByte();
            if (tag != 0x01)
            {
                SkipElement(reader);
                return false;
            }

            int len = ReadLength(reader);
            if (len != 1 || reader.BaseStream.Position >= reader.BaseStream.Length)
                return false;

            return reader.ReadByte() != 0;
        }

        private static string ReadASN1String(BinaryReader reader)
        {
            if (reader.BaseStream.Position >= reader.BaseStream.Length)
                return "none";

            byte tag = reader.ReadByte();

            if (tag != 0x04 && tag != 0x0A && tag != 0x0C && tag != 0x16 && tag != 0x1E && tag != 0x80 && tag != 0x81 && tag != 0x82 && tag != 0x8A && tag != 0x8B)
            {
                SkipElement(reader);
                return "none";
            }

            int len = ReadLength(reader);
            if (len <= 0 || reader.BaseStream.Position + len > reader.BaseStream.Length)
                return "none";

            byte[] data = reader.ReadBytes(len);

            try
            {
                return Encoding.UTF8.GetString(data);
            }
            catch
            {
                try
                {
                    return Encoding.ASCII.GetString(data);
                }
                catch
                {
                    return "binary_data";
                }
            }
        }

        private static void SkipElement(BinaryReader reader)
        {
            try
            {
                if (reader.BaseStream.Position >= reader.BaseStream.Length)
                    return;

                reader.ReadByte();
                int length = ReadLength(reader);
                if (length > 0 && reader.BaseStream.Position + length <= reader.BaseStream.Length)
                {
                    reader.BaseStream.Position += length;
                }
            }
            catch
            {
                // Ignore errors during skip
            }
        }

        // Operation Parsers تبقى كما هي...
        private bool ParseOperation(BinaryReader reader, byte opTag)
        {
            try
            {
                switch (opTag)
                {
                    case 0x60: _operation = "BindRequest"; return ParseBindRequest(reader);
                    case 0x61: _operation = "BindResponse"; return ParseBindResponse(reader);
                    case 0x62: _operation = "UnbindRequest"; return ParseUnbindRequest(reader);
                    case 0x63: _operation = "SearchRequest"; return ParseSearchRequest(reader);
                    case 0x64: _operation = "SearchResultEntry"; return ParseSearchResultEntry(reader);
                    case 0x65: _operation = "SearchResultDone"; return ParseResult(reader);
                    case 0x66: _operation = "ModifyRequest"; return ParseModifyRequest(reader);
                    case 0x67: _operation = "ModifyResponse"; return ParseResult(reader);
                    case 0x68: _operation = "AddRequest"; return ParseAddRequest(reader);
                    case 0x69: _operation = "DelRequest"; return ParseDelRequest(reader);
                    case 0x6A: _operation = "ModifyDNRequest"; return ParseModifyDNRequest(reader);
                    case 0x6B: _operation = "ModifyDNResponse"; return ParseResult(reader);
                    case 0x6C: _operation = "CompareRequest"; return ParseCompareRequest(reader);
                    case 0x6D: _operation = "CompareResponse"; return ParseResult(reader);
                    case 0x6E: _operation = "AbandonRequest"; return ParseAbandonRequest(reader);
                    case 0x77: _operation = "ExtendedRequest"; return ParseExtendedRequest(reader);
                    case 0x78: _operation = "ExtendedResponse"; return ParseExtendedResponse(reader);
                    default:
                        _operation = $"Unknown(0x{opTag:X2})";
                        SkipElement(reader);
                        return true;
                }
            }
            catch (Exception ex)
            {
                _parseError = $"Operation parsing failed: {ex.Message}";
                OptimizedLogger.LogImportant($"[LDAP-PARSE] {_parseError}");
                return false;
            }
        }

        private bool ParseBindRequest(BinaryReader reader)
        {
            try
            {
                int bindLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + bindLength;

                int version = ReadASN1Integer(reader);
                _attributes["Version"] = version.ToString();

                _dn = ReadASN1String(reader);

                if (reader.BaseStream.Position < endPos)
                {
                    byte authTag = reader.ReadByte();
                    if (authTag == 0x80)
                    {
                        _attributes["AuthenticationType"] = "Simple";
                        string password = ReadASN1String(reader);
                        _attributes["Password"] = string.IsNullOrEmpty(password) ? "(empty)" : "(hidden)";
                    }
                    else if (authTag == 0xA3)
                    {
                        _attributes["AuthenticationType"] = "SASL";
                        int saslLength = ReadLength(reader);
                        _attributes["Mechanism"] = ReadASN1String(reader);
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] BindRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseBindResponse(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                _resultCode = ReadASN1Integer(reader);
                _dn = ReadASN1String(reader);

                if (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    byte tag = reader.ReadByte();
                    if (tag == 0x04)
                    {
                        string diag = ReadASN1String(reader);
                        _attributes["DiagnosticMessage"] = diag;
                    }
                }

                _status = GetResultCodeDescription(_resultCode);
                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] BindResponse failed: {ex.Message}");
                return false;
            }
        }


        private bool ParseUnbindRequest(BinaryReader reader)
        {
            try
            {
                ReadLength(reader); // Should be 0 for unbind
                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] UnbindRequest failed: {ex.Message}");
                return false;
            }
        }
        private static string GetModifyOperationDescription(int operation)
        {
            return operation switch
            {
                0 => "Add",
                1 => "Delete",
                2 => "Replace",
                _ => $"Unknown({operation})"
            };
        }
        private static string GetSearchScopeDescription(int scope)
        {
            return scope switch
            {
                0 => "BaseObject",
                1 => "SingleLevel",
                2 => "WholeSubtree",
                _ => $"Unknown({scope})"
            };
        }
        private static string GetDerefAliasesDescription(int deref)
        {
            return deref switch
            {
                0 => "NeverDerefAliases",
                1 => "DerefInSearching",
                2 => "DerefFindingBaseObj",
                3 => "DerefAlways",
                _ => $"Unknown({deref})"
            };
        }
        private bool ParseSearchRequest(BinaryReader reader)
        {
            try
            {
                int searchLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + searchLength;

                _dn = ReadASN1String(reader);

                // Parse scope (0: base, 1: one, 2: sub)
                byte scopeTag = reader.ReadByte();
                int scope = ReadASN1Integer(reader);
                _attributes["Scope"] = GetSearchScopeDescription(scope);

                // Parse deref aliases
                byte derefTag = reader.ReadByte();
                int deref = ReadASN1Integer(reader);
                _attributes["DerefAliases"] = GetDerefAliasesDescription(deref);

                // Parse size limit
                byte sizeLimitTag = reader.ReadByte();
                int sizeLimit = ReadASN1Integer(reader);
                _attributes["SizeLimit"] = sizeLimit.ToString();

                // Parse time limit
                byte timeLimitTag = reader.ReadByte();
                int timeLimit = ReadASN1Integer(reader);
                _attributes["TimeLimit"] = timeLimit.ToString();

                // Parse types only
                byte typesOnlyTag = reader.ReadByte();
                bool typesOnly = ReadASN1Boolean(reader);
                _attributes["TypesOnly"] = typesOnly.ToString();

                // Parse filter
                if (reader.BaseStream.Position < endPos)
                {
                    _filter = ParseFilter(reader);
                }

                // Parse attributes
                if (reader.BaseStream.Position < endPos && reader.ReadByte() == 0x30)
                {
                    int attrsLength = ReadLength(reader);
                    long attrsEndPos = reader.BaseStream.Position + attrsLength;
                    int attrIndex = 1;

                    while (reader.BaseStream.Position < attrsEndPos)
                    {
                        string attr = ReadASN1String(reader);
                        if (!string.IsNullOrEmpty(attr) && attr != "none")
                        {
                            _attributes[$"RequestedAttribute{attrIndex++}"] = attr;
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] SearchRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseSearchResultEntry(BinaryReader reader)
        {
            try
            {
                int entryLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + entryLength;

                _dn = ReadASN1String(reader);

                // Parse attributes sequence
                if (reader.ReadByte() == 0x30)
                {
                    int attrsLength = ReadLength(reader);
                    long attrsEndPos = reader.BaseStream.Position + attrsLength;

                    while (reader.BaseStream.Position < attrsEndPos)
                    {
                        if (reader.ReadByte() == 0x30)
                        {
                            int attrLength = ReadLength(reader);
                            long attrEndPos = reader.BaseStream.Position + attrLength;

                            string attrType = ReadASN1String(reader);

                            // Parse attribute values
                            if (reader.ReadByte() == 0x31) // SET
                            {
                                int valuesLength = ReadLength(reader);
                                long valuesEndPos = reader.BaseStream.Position + valuesLength;
                                int valueIndex = 1;

                                while (reader.BaseStream.Position < valuesEndPos)
                                {
                                    string attrValue = ReadASN1String(reader);
                                    if (!string.IsNullOrEmpty(attrValue) && attrValue != "none")
                                    {
                                        _attributes[$"{attrType}_Value{valueIndex++}"] = attrValue;
                                    }
                                }
                            }

                            reader.BaseStream.Position = attrEndPos;
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] SearchResultEntry failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseResult(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                _resultCode = ReadASN1Integer(reader);
                _dn = ReadASN1String(reader);

                // Read diagnostic message if present
                if (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    byte tag = reader.ReadByte();
                    if (tag == 0x04) // OCTET STRING
                    {
                        string diag = ReadASN1String(reader);
                        _attributes["DiagnosticMessage"] = diag;
                    }
                }

                _status = GetResultCodeDescription(_resultCode);
                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] Result parsing failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseAddRequest(BinaryReader reader)
        {
            try
            {
                int addLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + addLength;

                _dn = ReadASN1String(reader);

                // Parse attributes sequence
                if (reader.ReadByte() == 0x30)
                {
                    int attrsLength = ReadLength(reader);
                    long attrsEndPos = reader.BaseStream.Position + attrsLength;

                    while (reader.BaseStream.Position < attrsEndPos)
                    {
                        if (reader.ReadByte() == 0x30)
                        {
                            int attrLength = ReadLength(reader);
                            long attrEndPos = reader.BaseStream.Position + attrLength;

                            string attrType = ReadASN1String(reader);

                            // Parse attribute values
                            if (reader.ReadByte() == 0x31) // SET
                            {
                                int valuesLength = ReadLength(reader);
                                long valuesEndPos = reader.BaseStream.Position + valuesLength;

                                // Read first value as example
                                if (reader.BaseStream.Position < valuesEndPos)
                                {
                                    string attrValue = ReadASN1String(reader);
                                    _attributes[$"Add_{attrType}"] = string.IsNullOrEmpty(attrValue) ? "(empty)" : "(value present)";
                                }
                            }

                            reader.BaseStream.Position = attrEndPos;
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] AddRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseDelRequest(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                _dn = ReadASN1String(reader);
                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] DelRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseModifyRequest(BinaryReader reader)
        {
            try
            {
                int modifyLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + modifyLength;

                _dn = ReadASN1String(reader);

                // Parse modifications sequence
                if (reader.ReadByte() == 0x30)
                {
                    int modsLength = ReadLength(reader);
                    long modsEndPos = reader.BaseStream.Position + modsLength;
                    int modIndex = 1;

                    while (reader.BaseStream.Position < modsEndPos)
                    {
                        if (reader.ReadByte() == 0x30)
                        {
                            int modLength = ReadLength(reader);
                            long modEndPos = reader.BaseStream.Position + modLength;

                            // Parse operation
                            byte opTag = reader.ReadByte();
                            int operation = ReadASN1Integer(reader);
                            _attributes[$"Modification{modIndex}_Operation"] = GetModifyOperationDescription(operation);

                            // Parse modification
                            if (reader.ReadByte() == 0x30)
                            {
                                int attrLength = ReadLength(reader);
                                long attrEndPos = reader.BaseStream.Position + attrLength;

                                string attrType = ReadASN1String(reader);

                                // Parse values
                                if (reader.ReadByte() == 0x31)
                                {
                                    int valuesLength = ReadLength(reader);
                                    _attributes[$"Modification{modIndex}_Attribute"] = attrType;
                                }

                                reader.BaseStream.Position = attrEndPos;
                            }

                            modIndex++;
                            reader.BaseStream.Position = modEndPos;
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] ModifyRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseModifyDNRequest(BinaryReader reader)
        {
            try
            {
                int modifyDNLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + modifyDNLength;

                _dn = ReadASN1String(reader);

                // New RDN
                string newRDN = ReadASN1String(reader);
                _attributes["NewRDN"] = newRDN;

                // Delete old RDN
                byte deleteOldTag = reader.ReadByte();
                bool deleteOldRDN = ReadASN1Boolean(reader);
                _attributes["DeleteOldRDN"] = deleteOldRDN.ToString();

                // New superior (optional)
                if (reader.BaseStream.Position < endPos)
                {
                    byte newSuperiorTag = reader.ReadByte();
                    if (newSuperiorTag == 0x80)
                    {
                        string newSuperior = ReadASN1String(reader);
                        _attributes["NewSuperior"] = newSuperior;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] ModifyDNRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseCompareRequest(BinaryReader reader)
        {
            try
            {
                int compareLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + compareLength;

                _dn = ReadASN1String(reader);

                // Parse attribute value assertion
                if (reader.ReadByte() == 0x30)
                {
                    int avaLength = ReadLength(reader);
                    string attribute = ReadASN1String(reader);
                    string value = ReadASN1String(reader);
                    _attributes["Compare"] = $"{attribute}={value}";
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] CompareRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseAbandonRequest(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                int abandonMessageId = ReadASN1Integer(reader);
                _attributes["AbandonMessageID"] = abandonMessageId.ToString();
                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] AbandonRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseExtendedRequest(BinaryReader reader)
        {
            try
            {
                int extendedLength = ReadLength(reader);
                long endPos = reader.BaseStream.Position + extendedLength;

                // Read OID if present
                if (reader.BaseStream.Position < endPos)
                {
                    byte oidTag = reader.ReadByte();
                    if (oidTag == 0x80)
                    {
                        string oid = ReadASN1String(reader);
                        _attributes["ExtendedOID"] = oid;
                        _operation = $"ExtendedRequest({oid})";
                    }
                }

                // Read value if present
                if (reader.BaseStream.Position < endPos)
                {
                    byte valueTag = reader.ReadByte();
                    if (valueTag == 0x81)
                    {
                        _attributes["ExtendedValue"] = "(present)";
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] ExtendedRequest failed: {ex.Message}");
                return false;
            }
        }

        private bool ParseExtendedResponse(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                _resultCode = ReadASN1Integer(reader);
                _dn = ReadASN1String(reader);

                // Read OID if present
                if (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    byte oidTag = reader.ReadByte();
                    if (oidTag == 0x8A)
                    {
                        string oid = ReadASN1String(reader);
                        _attributes["ResponseOID"] = oid;
                    }
                }

                // Read value if present
                if (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    byte valueTag = reader.ReadByte();
                    if (valueTag == 0x8B)
                    {
                        _attributes["ResponseValue"] = "(present)";
                    }
                }

                _status = GetResultCodeDescription(_resultCode);
                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] ExtendedResponse failed: {ex.Message}");
                return false;
            }
        }


        #region Filter Parsing

        private string ParseFilter(BinaryReader reader)
        {
            try
            {
                byte filterTag = reader.ReadByte();
                int filterLength = ReadLength(reader);

                switch (filterTag)
                {
                    case 0x87: // present
                        return $"Present: {ReadASN1String(reader)}";

                    case 0xA0: // and
                        return "And: " + ParseFilterSet(reader, filterLength);

                    case 0xA1: // or  
                        return "Or: " + ParseFilterSet(reader, filterLength);

                    case 0xA2: // not
                        return "Not: " + ParseFilter(reader);

                    case 0xA3: // equalityMatch
                        return ParseEqualityFilter(reader);

                    case 0xA4: // substrings
                        return ParseSubstringFilter(reader);

                    case 0xA5: // greaterOrEqual
                        return ParseComparisonFilter(reader, ">=");

                    case 0xA6: // lessOrEqual
                        return ParseComparisonFilter(reader, "<=");

                    case 0xA7: // approxMatch
                        return ParseComparisonFilter(reader, "~=");

                    case 0xA8: // extensibleMatch
                        return ParseExtensibleMatchFilter(reader);

                    default:
                        return $"Filter(0x{filterTag:X2})";
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[LDAP-PARSE] Filter parsing failed: {ex.Message}");
                return "filter_parse_error";
            }
        }

        private string ParseFilterSet(BinaryReader reader, int length)
        {
            long endPos = reader.BaseStream.Position + length;
            var filters = new List<string>();

            while (reader.BaseStream.Position < endPos)
            {
                filters.Add(ParseFilter(reader));
            }

            return string.Join(", ", filters);
        }

        private string ParseEqualityFilter(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                string attribute = ReadASN1String(reader);
                string value = ReadASN1String(reader);
                return $"{attribute}={value}";
            }
            catch
            {
                return "equality_parse_error";
            }
        }

        private string ParseComparisonFilter(BinaryReader reader, string operatorStr)
        {
            try
            {
                _ = ReadLength(reader);
                string attribute = ReadASN1String(reader);
                string value = ReadASN1String(reader);
                return $"{attribute}{operatorStr}{value}";
            }
            catch
            {
                return $"comparison_{operatorStr}_error";
            }
        }

        private string ParseSubstringFilter(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                string attribute = ReadASN1String(reader);

                // Parse substring sequence
                if (reader.ReadByte() == 0x30)
                {
                    int seqLength = ReadLength(reader);
                    var parts = new List<string>();

                    while (reader.BaseStream.Position < reader.BaseStream.Position + seqLength)
                    {
                        byte partType = reader.ReadByte();
                        string partValue = ReadASN1String(reader);

                        switch (partType)
                        {
                            case 0x80: parts.Add(partValue); break; // initial
                            case 0x81: parts.Add("*" + partValue); break; // any  
                            case 0x82: parts.Add(partValue + "*"); break; // final
                        }
                    }

                    return $"{attribute}={string.Join("", parts)}";
                }

                return $"{attribute}=*";
            }
            catch
            {
                return "substring_parse_error";
            }
        }

        private string ParseExtensibleMatchFilter(BinaryReader reader)
        {
            try
            {
                _ = ReadLength(reader);
                // Simplified extensible match parsing
                return "extensible_match";
            }
            catch
            {
                return "extensible_parse_error";
            }
        }


        private void ResetState()
        {
            _operation = "unknown";
            _dn = "none";
            _filter = "none";
            _messageId = -1;
            _resultCode = -1;
            _status = "unknown";
            _attributes.Clear();
            _isSuspicious = false;
            _parseError = string.Empty;
            _originalData = null;
        }

        private void UpdateResultFromState(LdapParseResult result)
        {
            result.Operation = _operation;
            result.DistinguishedName = _dn;
            result.Filter = _filter;
            result.SessionId = _messageId;
            result.ResultCode = _resultCode;
            result.Status = _status;
            result.Attributes = new Dictionary<string, string>(_attributes);
            result.IsSuspicious = _isSuspicious;
        }

        private void DetectSuspiciousBehavior()
        {
            if (_operation == "BindRequest" && _attributes.TryGetValue("AuthenticationType", out var auth))
            {
                if (auth == "Simple" && _attributes.GetValueOrDefault("Password") == "(empty)")
                {
                    _isSuspicious = true;
                    _attributes["SuspiciousReason"] = "Simple bind with empty password";
                }
            }

            if (_operation == "SearchRequest" && _filter.Contains("*"))
            {
                _isSuspicious = true;
                _attributes["SuspiciousReason"] = "Wildcard search filter";
            }

            if (_operation == "BindRequest" && _dn == "" && _attributes.GetValueOrDefault("AuthenticationType") == "Simple")
            {
                _isSuspicious = true;
                _attributes["SuspiciousReason"] = "Anonymous bind attempt";
            }

            if (_operation.Contains("Delete") || _operation.Contains("Modify"))
            {
                _isSuspicious = true;
                _attributes["SuspiciousReason"] = "Directory modification operation";
            }
        }

        private static string GetResultCodeDescription(int resultCode)
        {
            return resultCode switch
            {
                0 => "Success",
                1 => "OperationsError",
                2 => "ProtocolError",
                3 => "TimeLimitExceeded",
                4 => "SizeLimitExceeded",
                5 => "CompareFalse",
                6 => "CompareTrue",
                7 => "AuthMethodNotSupported",
                8 => "StrongAuthRequired",
                10 => "Referral",
                11 => "AdminLimitExceeded",
                12 => "UnavailableCriticalExtension",
                13 => "ConfidentialityRequired",
                14 => "SaslBindInProgress",
                16 => "NoSuchAttribute",
                17 => "UndefinedAttributeType",
                18 => "InappropriateMatching",
                19 => "ConstraintViolation",
                20 => "AttributeOrValueExists",
                21 => "InvalidAttributeSyntax",
                32 => "NoSuchObject",
                33 => "AliasProblem",
                34 => "InvalidDNSyntax",
                36 => "AliasDereferencingProblem",
                48 => "InappropriateAuthentication",
                49 => "InvalidCredentials",
                50 => "InsufficientAccessRights",
                51 => "Busy",
                52 => "Unavailable",
                53 => "UnwillingToPerform",
                54 => "LoopDetect",
                64 => "NamingViolation",
                65 => "ObjectClassViolation",
                66 => "NotAllowedOnNonLeaf",
                67 => "NotAllowedOnRDN",
                68 => "EntryAlreadyExists",
                69 => "ObjectClassModsProhibited",
                71 => "AffectsMultipleDSAs",
                80 => "Other",
                _ => $"Unknown({resultCode})"
            };
        }

        public void Dispose()
        {
            // Cleanup if needed
        }
    }

    public class LdapParseResult
    {
        public string Operation { get; set; } = "unknown";
        public string DistinguishedName { get; set; } = "none";
        public string Filter { get; set; } = "none";
        public int SessionId { get; set; } = -1;
        public int ResultCode { get; set; } = -1;
        public string Status { get; set; } = "unknown";
        public Dictionary<string, string> Attributes { get; set; } = new();
        public bool IsSuspicious { get; set; } = false;

        public override string ToString()
        {
            return $"LDAP Operation: {Operation}, DN: {DistinguishedName}, Status: {Status}, Suspicious: {IsSuspicious}";
        }
    }
    public class DirectoryServiceParser
    {
        public DirectoryServiceParseResult Parse(byte[] data)
        {
            var result = new DirectoryServiceParseResult();

            if (data == null || data.Length < 4)
                return result;

            try
            {
                using var ms = new MemoryStream(data);
                using var reader = new BinaryReader(ms);

                // Read 4-byte big endian length
                byte[] lengthBytes = reader.ReadBytes(4);
                if (lengthBytes.Length == 4)
                {
                    result.TotalLength = (lengthBytes[0] << 24) | (lengthBytes[1] << 16) |
                                       (lengthBytes[2] << 8) | lengthBytes[3];
                }

                // Try to read operation type
                if (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    byte opType = reader.ReadByte();
                    result.OperationType = opType;
                    result.OperationName = GetOperationName(opType);
                }

                // **تحسين استخراج البيانات**: ابحث عن patterns معروفة
                result.Strings = ExtractMeaningfulData(data, 8);

                // حاول استخراج Distinguished Names
                result.DistinguishedNames = ExtractDistinguishedNames(data);

                // حاول استخراج Operation-specific data
                ExtractOperationData(data, result);

                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }
        }

        private List<string> ExtractMeaningfulData(byte[] data, int startIndex)
        {
            var meaningfulData = new List<string>();
            var currentString = new StringBuilder();

            for (int i = startIndex; i < data.Length; i++)
            {
                byte b = data[i];

                // Printable ASCII range
                if (b >= 0x20 && b <= 0x7E)
                {
                    currentString.Append((char)b);
                }
                else if (currentString.Length > 0)
                {
                    string str = currentString.ToString();

                    // **أضف فقط البيانات ذات المعنى**
                    if (IsMeaningfulData(str))
                    {
                        meaningfulData.Add(str);
                    }
                    currentString.Clear();
                }
            }

            // Add any remaining meaningful string
            string finalStr = currentString.ToString();
            if (IsMeaningfulData(finalStr))
            {
                meaningfulData.Add(finalStr);
            }

            return meaningfulData;
        }

        private bool IsMeaningfulData(string str)
        {
            if (string.IsNullOrEmpty(str) || str.Length < 3)
                return false;

            // **ابحث عن patterns مفيدة**
            return str.Contains("CN=") || str.Contains("DC=") ||
                   str.Contains("OU=") || str.Contains("objectClass") ||
                   str.Contains("sAMAccountName") || str.Contains("userPrincipalName") ||
                   str.Contains("memberOf") || str.Contains("distinguishedName") ||
                   str.StartsWith("LDAP") || str.Contains("GUID") ||
                   str.Contains("SID") || str.Contains("NTLM") ||
                   (str.Length >= 8 && !str.All(c => char.IsLetterOrDigit(c)));
        }

        private List<string> ExtractDistinguishedNames(byte[] data)
        {
            var dns = new List<string>();
            string dataStr = Encoding.UTF8.GetString(data);

            // ابحث عن patterns الـ DN
            var patterns = new[] { "CN=", "DC=", "OU=" };
            foreach (var pattern in patterns)
            {
                int index = 0;
                while ((index = dataStr.IndexOf(pattern, index)) != -1)
                {
                    int end = dataStr.IndexOf('\0', index);
                    if (end == -1) end = Math.Min(index + 200, dataStr.Length);

                    string dn = dataStr.Substring(index, end - index);
                    if (dn.Length > 5 && dn.Length < 500 && !dns.Contains(dn))
                    {
                        dns.Add(dn);
                    }
                    index = end + 1;
                }
            }

            return dns;
        }

        private void ExtractOperationData(byte[] data, DirectoryServiceParseResult result)
        {
            // حسب نوع العملية، استخرج بيانات محددة
            switch (result.OperationType)
            {
                case 0x02: // Bind Response
                    result.Attributes["BindResult"] = ExtractBindResult(data);
                    break;
                case 0x04: // Search Response  
                    result.Attributes["SearchResults"] = ExtractSearchResults(data);
                    break;
                case 0x05: // Modify
                    result.Attributes["ModifyTarget"] = ExtractModifyTarget(data);
                    break;
            }
        }

        private string ExtractBindResult(byte[] data)
        {
            // ابحث عن result codes في الـ Bind Response
            if (data.Length > 10)
            {
                // موقع تقريبي لـ result code
                int resultCode = data[9];
                return $"BindResult: {GetBindResultDescription(resultCode)}";
            }
            return "Unknown";
        }

        private string GetBindResultDescription(int code)
        {
            return code switch
            {
                0 => "Success",
                1 => "InvalidCredentials",
                7 => "InvalidCredentials",
                8 => "ConstraintViolation",
                49 => "InvalidCredentials",
                _ => $"Code_{code}"
            };
        }

        private string ExtractSearchResults(byte[] data)
        {
            // محاولة استخراج عدد النتائج من Search Response
            try
            {
                if (data.Length > 20)
                {
                    // هذا موقع تقريبي لعدد النتائج في بعض بروتوكولات Directory Service
                    int resultsCount = data[15];
                    return $"ResultsCount: {resultsCount}";
                }
            }
            catch
            {
                // تجاهل الأخطاء
            }
            return "Unknown";
        }

        private string ExtractModifyTarget(byte[] data)
        {
            // محاولة استخراج الـ DN اللي بيتعدل
            try
            {
                string dataStr = Encoding.UTF8.GetString(data);
                int cnIndex = dataStr.IndexOf("CN=");
                if (cnIndex != -1)
                {
                    int end = dataStr.IndexOf('\0', cnIndex);
                    if (end == -1) end = Math.Min(cnIndex + 100, dataStr.Length);
                    return dataStr.Substring(cnIndex, end - cnIndex);
                }
            }
            catch
            {
                // تجاهل الأخطاء
            }
            return "Unknown";
        }

        private string GetOperationName(byte opType)
        {
            return opType switch
            {
                0x01 => "Bind",
                0x02 => "BindResponse",
                0x03 => "Search",
                0x04 => "SearchResponse",
                0x05 => "Modify",
                0x06 => "ModifyResponse",
                0x09 => "Abandon",
                0x0A => "Extended",
                0x0B => "ExtendedResponse",
                _ => $"Unknown(0x{opType:X2})"
            };
        }
    }

    public class DirectoryServiceParseResult
    {
        public int TotalLength { get; set; }
        public byte OperationType { get; set; }
        public string OperationName { get; set; } = "unknown";
        public List<string> Strings { get; set; } = new List<string>();
        public List<string> DistinguishedNames { get; set; } = new List<string>();
        public Dictionary<string, string> Attributes { get; set; } = new Dictionary<string, string>();
        public string Error { get; set; } = "";
    }

        public static class Port389ProtocolDetector
        {
            public static string DetectProtocol(byte[] data)
            {
                if (data == null || data.Length == 0)
                    return "unknown";

                byte firstByte = data[0];

                // Standard LDAP starts with 0x30 (BER sequence)
                if (firstByte == 0x30)
                    return "ldap";

                // Global Catalog/Directory Service often starts with 0x00
                if (firstByte == 0x00 && data.Length >= 4)
                {
                    // Check for common directory service patterns
                    try
                    {
                        using var ms = new MemoryStream(data);
                        using var reader = new BinaryReader(ms);

                        // Read 4-byte length prefix (common in directory protocols)
                        int lengthPrefix = (reader.ReadByte() << 24) | (reader.ReadByte() << 16) |
                                         (reader.ReadByte() << 8) | reader.ReadByte();

                        if (lengthPrefix > 0 && lengthPrefix <= data.Length - 4)
                        {
                            // This is likely directory service/GC traffic
                            return "directory_service";
                        }
                    }
                    catch
                    {
                        // If we can't parse, still treat as directory service
                        return "directory_service";
                    }
                }

                // TLS/Encrypted traffic
                if (firstByte == 0x16 || firstByte == 0x14 || firstByte == 0x15 || firstByte == 0x17)
                    return "tls";

                // Microsoft RPC or encrypted traffic patterns
                if (firstByte == 0xC2 || firstByte == 0x01)
                    return "encrypted_or_binary";

                // Check for HTTP traffic on port 389 (misconfiguration)
                if (data.Length >= 4)
                {
                    string start = Encoding.ASCII.GetString(data, 0, Math.Min(4, data.Length));
                    if (start == "GET " || start == "POST" || start == "HEAD" || start == "PUT ")
                        return "http_on_ldap_port";
                }

                // Check for SSH traffic
                if (data.Length >= 4 && Encoding.ASCII.GetString(data, 0, 4) == "SSH-")
                    return "ssh_on_ldap_port";

                return "unknown";
            }

            public static bool IsLikelyDirectoryService(byte[] data)
            {
                if (data == null || data.Length < 4) return false;

                // Directory service often has 4-byte length prefix starting with 0x00
                if (data[0] == 0x00 && data[1] == 0x00)
                {
                    // Check if the length prefix makes sense
                    try
                    {
                        int length = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
                        return length > 0 && length <= data.Length - 4;
                    }
                    catch
                    {
                        return false;
                    }
                }

                return false;
            }

            public static string GetProtocolDescription(byte[] data)
            {
                if (data == null || data.Length == 0)
                    return "Empty data";

                string protocol = DetectProtocol(data);
                byte firstByte = data[0];

                var description = new StringBuilder();
                description.Append($"Protocol: {protocol}, First byte: 0x{firstByte:X2}");

                // Add more detailed analysis
                switch (protocol)
                {
                    case "ldap":
                        description.Append(" - Standard LDAP protocol");
                        break;
                    case "directory_service":
                        description.Append(" - Directory Service/Global Catalog");
                        if (data.Length >= 4)
                        {
                            int length = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
                            description.Append($", Length: {length}");
                        }
                        break;
                    case "tls":
                        description.Append(" - TLS/SSL encrypted traffic");
                        description.Append($", Content Type: {GetTlsContentType(firstByte)}");
                        break;
                    case "encrypted_or_binary":
                        description.Append(" - Encrypted or binary protocol");
                        if (data.Length >= 2)
                        {
                            description.Append($", Second byte: 0x{data[1]:X2}");
                        }
                        break;
                    case "http_on_ldap_port":
                        description.Append(" - HTTP traffic on LDAP port (misconfiguration)");
                        break;
                    case "ssh_on_ldap_port":
                        description.Append(" - SSH traffic on LDAP port (misconfiguration)");
                        break;
                    default:
                        description.Append(" - Unknown protocol");
                        break;
                }

                // Analyze data patterns
                description.Append($", Total length: {data.Length}");

                // Count printable characters
                int printable = 0;
                for (int i = 0; i < Math.Min(50, data.Length); i++)
                {
                    if (data[i] >= 0x20 && data[i] <= 0x7E) printable++;
                }
                description.Append($", Printable: {printable}/{Math.Min(50, data.Length)}");

                return description.ToString();
            }

            private static string GetTlsContentType(byte contentType)
            {
                return contentType switch
                {
                    0x14 => "ChangeCipherSpec",
                    0x15 => "Alert",
                    0x16 => "Handshake",
                    0x17 => "ApplicationData",
                    _ => $"Unknown(0x{contentType:X2})"
                };
            }
        }
    }

#endregion