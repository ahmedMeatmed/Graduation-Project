<template>
  <div class="container my-5">
    <!-- <h1 class="fw-bold text-center mb-4">Settings</h1> -->

    <div class="row g-4">

      <!-- General Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">General Settings</h4>
            <div class="mb-3">
              <label class="form-label">Project Name</label>
              <input type="text" class="form-control" disabled value="AEGIS">
            </div>
            <div class="form-check form-switch">
              <input class="form-check-input p-2" type="checkbox" style="cursor: pointer;">
              <label class="form-check-label">Theme</label>
            </div>
        </div>
      </div>


     <!-- Logging Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Logging Settings</h4>

          <div class="mb-3">
            <label class="form-label">Enable Detailed Logs</label>
            <select class="form-select" v-model="settings.enableDetailedLogs">
              <option :value="true">True</option>
              <option :value="false">False</option>
            </select>
          </div>

          <div class="mb-3">
            <label class="form-label">Log Retention (days)</label>
            <input type="number" class="form-control" v-model="settings.logRetention" />
          </div>
        </div>
      </div>

      <SignatureSettings />
      <UserSettings />

      <!-- remained settings -->
       <!-- Detection Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Detection Settings</h4>

          <div class="mb-3">
            <label class="form-label">Port Scan Threshold</label>
            <input type="number" class="form-control" v-model="settings.portScanThreshold" />
          </div>

          <div class="mb-3">
            <label class="form-label">Deauth Threshold</label>
            <input type="number" class="form-control" v-model="settings.deauthThreshold" />
          </div>

          <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" v-model="settings.enableHttpInspection" />
            <label class="form-check-label">Enable HTTP Inspection</label>
          </div>
        </div>
      </div>

      <!-- Network Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Network Settings</h4>

          <div class="mb-3">
            <label class="form-label">Internal IP Prefix</label>
            <input type="text" class="form-control" v-model="settings.internalIpPrefix" />
          </div>

          <div class="mb-3">
            <label class="form-label">DNS Servers</label>
            <input type="text" class="form-control" v-model="settings.dnsServers" />
          </div>

          <div class="mb-3">
            <label class="form-label">HTTP Ports</label>
            <input type="text" class="form-control" v-model="settings.httpPorts" />
          </div>
        </div>
      </div>

      <!-- Performance Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Performance Settings</h4>

          <div class="mb-3">
            <label class="form-label">Max Flow Count</label>
            <input type="number" class="form-control" v-model="settings.maxFlowCount" />
          </div>

          <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" v-model="settings.enablePerformance" />
            <label class="form-check-label">Enable Performance Mode</label>
          </div>
        </div>
      </div>

      <!-- Capture Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Capture Settings</h4>

          <div class="mb-3">
            <label class="form-label">Capture Mode</label>
            <select class="form-select" v-model="settings.captureMode">
              <option value="live">Live Interface</option>
              <option value="Pcap">PCAP File</option>
            </select>
          </div>

          <div class="mb-3">
            <label class="form-label">PCAP File Path</label>
            <input
              type="file"
              class="form-control"
            />
          </div>
        </div>
      </div>

     

    </div>

    <!-- Save Button -->
    <div class="text-end mt-4">
      <button class="btn btn-primary" @click="saveSettings">
        Save Settings
      </button>
    </div>
  </div>      
</template>

<script setup>
import SignatureSettings from './SignatureSettings.vue';
import UserSettings from './UserSettings.vue';
import { reactive } from "vue";

const settings = reactive({
  captureMode: "live",
  pcapFilePath: "",
  portScanThreshold: 10,
  deauthThreshold: 15,
  enableHttpInspection: true,
  internalIpPrefix: "192.168.1.0/24",
  dnsServers: "8.8.8.8,1.1.1.1",
  httpPorts: "80,8080,443",
  maxFlowCount: 10000,
  enablePerformance: true,
  enableDetailedLogs: false,
  logRetention: 30
});

function saveSettings() {
  console.log("Saved settings:", settings);

}
</script>

