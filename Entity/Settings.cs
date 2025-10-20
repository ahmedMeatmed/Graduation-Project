using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a configuration setting for the Intrusion Detection System.
    /// Stores system parameters, thresholds, and operational configurations that control IDS behavior and functionality.
    /// </summary>
    public class Settings
    {
        int id;
        string settingName;
        string settingValue;
        string dataType;
        string category;
        string desc;
        DateTime lastModified;

        /// <summary>Unique identifier for the setting record</summary>
        public int Id { get => id; set => id = value; }

        /// <summary>Name of the configuration setting (e.g., "DetectionThreshold", "LogRetentionDays", "AlertEmailEnabled")</summary>
        public string SettingName { get => settingName; set => settingName = value; }

        /// <summary>Current value of the setting as a string (will be parsed according to DataType)</summary>
        public string SettingValue { get => settingValue; set => settingValue = value; }

        /// <summary>Data type of the setting value (e.g., "int", "bool", "string", "double", "DateTime")</summary>
        public string DataType { get => dataType; set => dataType = value; }

        /// <summary>Category grouping for organizational purposes (e.g., "Detection", "Logging", "Network", "Performance")</summary>
        public string Category { get => category; set => category = value; }

        /// <summary>Description explaining the purpose and usage of the setting</summary>
        public string Desc { get => desc; set => desc = value; }

        /// <summary>Timestamp when this setting was last modified</summary>
        public DateTime LastModified { get => lastModified; set => lastModified = value; }

        /// <summary>
        /// Initializes a new instance of the Settings class with specified parameters.
        /// </summary>
        /// <param name="id">Unique identifier for the setting record</param>
        /// <param name="settingName">Name of the configuration setting</param>
        /// <param name="settingValue">Current value of the setting as a string</param>
        /// <param name="dataType">Data type of the setting value</param>
        /// <param name="category">Category grouping for organizational purposes</param>
        /// <param name="desc">Description explaining the purpose and usage</param>
        /// <param name="lastModified">Timestamp when this setting was last modified</param>
        internal Settings(int id, string settingName, string settingValue, string dataType,
            string category, string desc, DateTime lastModified)
        {
            this.id = id;
            this.settingName = settingName;
            this.settingValue = settingValue;
            this.dataType = dataType;
            this.category = category;
            this.desc = desc;
            this.lastModified = lastModified;
        }

        /// <summary>
        /// Initializes a new instance of the Settings class as a copy of an existing Settings object.
        /// </summary>
        /// <param name="s">Source Settings object to copy from</param>
        internal Settings(Settings s) : this(s.Id, s.settingName, s.settingValue, s.dataType, s.category, s.desc, s.lastModified) { }

        /// <summary>
        /// Creates a deep copy of the current Settings instance.
        /// </summary>
        /// <returns>A new Settings object that is an exact copy of the current instance</returns>
        public Settings Clone()
        {
            return new Settings(this);
        }
    }
}