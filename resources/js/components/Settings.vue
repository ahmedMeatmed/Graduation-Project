<template>
  <div class="container my-5">
    <!-- <h1 class="fw-bold text-center mb-4">Settings</h1> -->

    <div class="row g-4">

      <!-- General Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">General Settings</h4>
          <form>
            <div class="mb-3">
              <label class="form-label">Project Name</label>
              <input type="text" class="form-control" v-model="settings.projectName">
            </div>
            <div class="mb-3">
              <label class="form-label">Theme</label>
              <select class="form-select" v-model="settings.theme">
                <option value="light">Light</option>
                <option value="dark">Dark</option>
              </select>
            </div>
            <div class="form-check form-switch">
              <input class="form-check-input" type="checkbox" v-model="settings.notifications">
              <label class="form-check-label">Enable Notifications</label>
            </div>
          </form>
        </div>
      </div>

      <!-- Alerts Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Alerts Settings</h4>
          <form>
            <div class="form-check">
              <input class="form-check-input" type="checkbox" v-model="settings.alerts.enabled">
              <label class="form-check-label">Enable Alerts</label>
            </div>
            <div class="mb-3 mt-3">
              <label class="form-label">Alert Severity</label>
              <select class="form-select" v-model="settings.alerts.severity">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
          </form>
        </div>
      </div>

      <!-- Logs Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Logs Settings</h4>
          <form>
            <div class="mb-3">
              <label class="form-label">Log Retention (days)</label>
              <input type="number" class="form-control" v-model="settings.logs.retention">
            </div>
            <button class="btn btn-outline-primary btn-sm">
              Export Logs
            </button>
          </form>
        </div>
      </div>

      <!-- User Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">User Settings</h4>
          <form>
            <div class="mb-3">
              <label class="form-label">Change Password</label>
              <input type="password" class="form-control" placeholder="New Password">
            </div>
            <div class="mb-3">
              <label class="form-label">Confirm Password</label>
              <input type="password" class="form-control" placeholder="Confirm Password">
            </div>
            <button class="btn btn-primary btn-sm">Update Password</button>
          </form>
        </div>
      </div>
    </div>

    <!-- Save Button -->
    <div class="text-center mt-4">
      <button class="btn btn-success px-4" @click="saveSettings">Save Changes</button>
    </div>
  </div>
</template>

<script setup>
import { reactive } from "vue";

const settings = reactive({
  projectName: "IDS System",
  theme: "light",
  notifications: true,
  alerts: {
    enabled: true,
    severity: "high",
  },
  logs: {
    retention: 30, // days
  },
});

function saveSettings() {
  alert("Settings saved successfully! ✅\n" + JSON.stringify(settings, null, 2));
}
</script>
