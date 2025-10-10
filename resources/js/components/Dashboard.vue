<template>
  <div class="container my-5">
    <!-- <h1 class="fw-bold mb-4 text-center">Dashboard</h1> -->

    <!-- Quick Stats -->
    <div class="row g-4 mb-4">
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-exclamation-triangle-fill fs-2 mb-2 text-primary"></i>
          <h5>Total Alerts</h5>
          <h3 class="fw-bold">{{ data.alerts.length }}</h3>
        </div>
      </div>
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-box-arrow-in-down-right fs-2 mb-2 text-primary"></i>
          <h5>Active Logs</h5>
          <h3 class="fw-bold">{{ data.logs.length }}</h3>
        </div>
      </div>
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-people-fill fs-2 mb-2 text-primary"></i>
          <h5>Users</h5>
          <!-- <h3 class="fw-bold">{{ card.value }}</h3> -->
          <h3 class="fw-bold">123</h3>
        </div>
      </div>
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-cpu-fill fs-2 mb-2 text-primary"></i>
          <h5>System Status</h5>
          <h3 class="fw-bold">{{ systemStatus(data.alerts.length) }}</h3>
        </div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="row g-4 mb-4">
      <!-- Alerts Chart -->
      <div class="col-md-6">
        <div class="card shadow p-3">
          <h5 class="fw-semibold mb-3">Alerts Overview</h5>
          <canvas id="alertsChart" ></canvas>
        </div>
      </div>

      <!-- Logs Chart -->
      <div class="col-md-6">
        <div class="card shadow p-3">
          <h5 class="fw-semibold mb-3">Logs Activity</h5>
          <canvas id="logsChart"></canvas>
        </div>
      </div>
    </div>

    <!-- Recent Alerts Table -->
    <div class="card shadow p-3" style="height: 20em; overflow-y: scroll;">
      <h5 class="fw-semibold mb-3">Recent Alerts</h5>
      <table class="table table-hover">
        <thead>
          <tr>
            <th>#</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Source IP</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          <tr 
          v-for="(alert,index) in recentAlerts" :key="alert.AlertID"
          
          >
            <td>{{index + 1}}</td>
            <td>{{alert.AttackType}}</td>
            <td><span :class="severityClass(alert.Severity)">{{ alert.Severity }}</span></td>
            <td><router-link :to="singleAlert(alert.AlertID)">{{ alert.SourceIP }}</router-link></td>
            <td>{{ alert.Timestamp }}</td>
          </tr>
        </tbody>
      </table>
    </div>

  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useDataStore } from '../stores/dataStore';
import Chart from "chart.js/auto";


// useDataStore().FetchAlerts();
// useDataStore().FetchLogs();
const data = useDataStore();

const systemStatus =(noAlerts)=>{
  if(noAlerts < 3) return "Healthy";
  if(noAlerts > 3 && noAlerts < 7) return "Medium";
  if(noAlerts > 7) return "Weak";
}
// Severity color helper
const severityClass= (severity) => {
  if (severity === "High") return "badge bg-danger";
  if (severity === "Medium") return "badge bg-warning text-dark";
  if (severity === "Low") return "badge bg-success";
  return "badge bg-secondary";
}

const singleAlert = (alertId)=>{
  return `alerts/${alertId}`;
}

const highAlert = computed(() =>
  useDataStore().alerts.filter(a => a.Severity === "High").length
);
const midAlert = computed(() =>
  useDataStore().alerts.filter(a => a.Severity === "Medium").length
);
const lowAlert = computed(() =>
  useDataStore().alerts.filter(a => a.Severity === "Low").length
);

const recentAlerts = data.alerts.filter(a => a.Status === "New" || a.Status === "Investigating");


// Charts
onMounted(() => {
  // Alerts chart
  new Chart(document.getElementById("alertsChart"), {
    type: "doughnut",
    data: {
      labels: ["High", "Medium", "Low"],
      datasets: [
        {
          data: [highAlert.value,midAlert.value,lowAlert.value],
          backgroundColor: ["#dc3545", "#ffc107", "#198754"],
        },
      ],
    },
  });

  // Logs chart
  new Chart(document.getElementById("logsChart"), {
    type: "line",
    data: {
      labels: ["Sat","Sun","Mon", "Tue", "Wed", "Thu", "Fri"],
      datasets: [
        {
          label: "Logs",
          data: [50, 75, 100, 60, 120, 80, 95],
          fill: true,
          borderColor: "#0d6efd",
          backgroundColor: "rgba(13,110,253,0.1)",
        },
      ],
    },
  });
  
});
</script>
