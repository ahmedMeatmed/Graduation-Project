using IDSApp.Collection;
using IDSApp.Entity;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for application settings management with built-in caching for performance.
    /// This class serves as a facade to the data access layer with additional caching capabilities for frequently accessed settings.
    /// </summary>
    public static class SettingBLL
    {
        private static readonly ConcurrentDictionary<string, string> _settingsCache = new();
        private static DateTime _lastCacheUpdate = DateTime.MinValue;
        private static readonly TimeSpan _cacheTimeout = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Retrieves all settings from the system.
        /// </summary>
        /// <returns>A collection of Settings objects containing all configuration settings in the system.</returns>
        public static SettingCollection GetAll()
        {
            return DAL.SettingDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific setting by its unique identifier.
        /// </summary>
        /// <param name="id">The SettingID of the setting to retrieve.</param>
        /// <returns>A Settings object if found; otherwise, null.</returns>
        public static Settings GetById(int id)
        {
            return DAL.SettingDal.GetById(id);
        }

        /// <summary>
        /// Retrieves a specific setting by its name.
        /// </summary>
        /// <param name="name">The name of the setting to retrieve.</param>
        /// <returns>A Settings object if found; otherwise, null.</returns>
        public static Settings GetByName(string name)
        {
            return DAL.SettingDal.GetByName(name);
        }

        /// <summary>
        /// Creates a new setting in the system and clears the settings cache.
        /// </summary>
        /// <param name="settingName">The unique name identifier for the setting.</param>
        /// <param name="settingValue">The value of the setting.</param>
        /// <param name="dataType">The data type of the setting value (e.g., String, Integer, Boolean).</param>
        /// <param name="category">The category grouping for the setting (e.g., Network, Security, Performance).</param>
        /// <param name="desc">A description of what the setting controls.</param>
        /// <param name="lastModified">The date and time when the setting was last modified.</param>
        /// <returns>true if the setting was successfully created; otherwise, false.</returns>
        public static bool Insert(string settingName, string settingValue, string dataType, string category, string desc, DateTime lastModified)
        {
            // Clear cache when inserting new settings
            _settingsCache.Clear();
            _lastCacheUpdate = DateTime.MinValue;
            return DAL.SettingDal.Insert(settingName, settingValue, dataType, category, desc, lastModified);
        }

        /// <summary>
        /// Updates an existing setting and clears the settings cache.
        /// </summary>
        /// <param name="id">The SettingID of the setting to update.</param>
        /// <param name="settingName">The updated setting name.</param>
        /// <param name="settingValue">The updated setting value.</param>
        /// <param name="dataType">The updated data type.</param>
        /// <param name="category">The updated category.</param>
        /// <param name="desc">The updated description.</param>
        /// <param name="lastModified">The updated last modified timestamp.</param>
        /// <returns>The number of rows affected by the update operation.</returns>
        public static int Update(int id, string settingName, string settingValue, string dataType, string category, string desc, DateTime lastModified)
        {
            // Clear cache when updating settings
            _settingsCache.Clear();
            _lastCacheUpdate = DateTime.MinValue;
            return DAL.SettingDal.Update(id, settingName, settingValue, dataType, category, desc, lastModified);
        }

        /// <summary>
        /// Deletes a specific setting from the system and clears the settings cache.
        /// </summary>
        /// <param name="id">The SettingID of the setting to delete.</param>
        /// <returns>true if the setting was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int id)
        {
            // Clear cache when deleting settings
            _settingsCache.Clear();
            _lastCacheUpdate = DateTime.MinValue;
            return DAL.SettingDal.Delete(id);
        }

        /// <summary>
        /// Retrieves the internal IP address prefix used for network segmentation.
        /// </summary>
        /// <returns>The IP address prefix for internal network addresses.</returns>
        public static string GetInternalIpPrefix()
        {
            return DAL.SettingDal.GetInternalIpPrefix();
        }

        /// <summary>
        /// Retrieves a setting value from cache with optional default value.
        /// </summary>
        /// <param name="key">The name of the setting to retrieve.</param>
        /// <param name="defaultValue">The default value to return if the setting is not found.</param>
        /// <returns>The setting value if found; otherwise, the specified default value.</returns>
        public static string GetSetting(string key, string defaultValue = "")
        {
            RefreshCacheIfNeeded();
            return _settingsCache.TryGetValue(key, out string value) ? value : defaultValue;
        }

        /// <summary>
        /// Retrieves a typed setting value from cache with optional default value.
        /// </summary>
        /// <typeparam name="T">The type to convert the setting value to (e.g., int, bool, double).</typeparam>
        /// <param name="key">The name of the setting to retrieve.</param>
        /// <param name="defaultValue">The default value to return if the setting is not found or conversion fails.</param>
        /// <returns>The typed setting value if found and convertible; otherwise, the specified default value.</returns>
        public static T GetSetting<T>(string key, T defaultValue = default(T))
        {
            var stringValue = GetSetting(key);
            if (string.IsNullOrEmpty(stringValue))
                return defaultValue;

            try
            {
                return (T)Convert.ChangeType(stringValue, typeof(T));
            }
            catch
            {
                return defaultValue;
            }
        }

        /// <summary>
        /// Retrieves all settings as a dictionary from the cache.
        /// </summary>
        /// <returns>A dictionary containing all cached setting names and values.</returns>
        public static Dictionary<string, string> GetAllCachedSettings()
        {
            RefreshCacheIfNeeded();
            return _settingsCache.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        /// <summary>
        /// Forces a refresh of the settings cache by clearing and reloading all settings.
        /// </summary>
        public static void RefreshSettingsCache()
        {
            _lastCacheUpdate = DateTime.MinValue;
            RefreshCacheIfNeeded();
        }

        /// <summary>
        /// Refreshes the settings cache if the cache has expired or has not been initialized.
        /// </summary>
        private static void RefreshCacheIfNeeded()
        {
            if (DateTime.Now - _lastCacheUpdate > _cacheTimeout)
            {
                try
                {
                    var settings = GetAll();
                    _settingsCache.Clear();

                    foreach (var setting in settings)
                    {
                        _settingsCache[setting.SettingName] = setting.SettingValue;
                    }

                    _lastCacheUpdate = DateTime.Now;
                    Console.WriteLine($"Settings cache refreshed: {_settingsCache.Count} settings loaded");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error refreshing settings cache: {ex.Message}");
                }
            }
        }

        // Convenience methods for common settings

        /// <summary>
        /// Retrieves the port scan detection threshold.
        /// </summary>
        /// <returns>The number of port scan attempts required to trigger an alert.</returns>
        public static int GetPortScanThreshold() => GetSetting("PortScanThreshold", 5);

        /// <summary>
        /// Retrieves the deauthentication attack detection threshold.
        /// </summary>
        /// <returns>The number of deauth frames required to trigger an alert.</returns>
        public static int GetDeauthThreshold() => GetSetting("DeauthThreshold", 15);

        /// <summary>
        /// Retrieves the HTTP body threat detection threshold.
        /// </summary>
        /// <returns>The number of threat indicators in HTTP body required to trigger an alert.</returns>
        public static int GetHttpBodyThreatThreshold() => GetSetting("HttpBodyThreatThreshold", 2);

        /// <summary>
        /// Retrieves the performance logging enablement setting.
        /// </summary>
        /// <returns>true if performance logging is enabled; otherwise, false.</returns>
        public static bool GetEnablePerformanceLogging() => GetSetting("EnablePerformanceLogging", true);

        /// <summary>
        /// Retrieves the network interface setting for packet capture.
        /// </summary>
        /// <returns>The name of the network interface to monitor.</returns>
        public static string GetNetworkInterface() => GetSetting("NetworkInterface", "");
    }
}