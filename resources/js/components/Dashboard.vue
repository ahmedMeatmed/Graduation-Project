<template>
  <div class="container my-5">
    <!-- <h1 class="fw-bold mb-4 text-center">Dashboard</h1> -->

    <!-- Quick Stats -->
    <div class="row g-4 mb-4">
      <div class="col-md-3" v-for="card in statsCards" :key="card.title">
        <div class="card shadow text-center p-3">
          <i :class="card.icon + ' fs-2 mb-2 text-primary'"></i>
          <!-- <h5>{{ card.title }}</h5> -->
          <h5>123</h5>
          <!-- <h3 class="fw-bold">{{ card.value }}</h3> -->
          <h3 class="fw-bold">123</h3>
        </div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="row g-4 mb-4">
      <!-- Alerts Chart -->
      <div class="col-md-6">
        <div class="card shadow p-3">
          <h5 class="fw-semibold mb-3">Alerts Overview</h5>
          <canvas id="alertsChart"></canvas>
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
    <div class="card shadow p-3">
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
          <tr v-for="(alert, index) in recentAlerts" :key="index">
            <!-- <td>{{ index + 1 }}</td> -->
            <td>123</td>
            <!-- <td>{{ alert.type }}</td> -->
            <td>123</td>
            <td>
              <span :class="severityClass(alert.severity)">
                {{ alert.severity }}
              </span>
            </td>
            <td>{{ alert.ip }}</td>
            <td>{{ alert.time }}</td>
          </tr>
        </tbody>
      </table>
    </div>

  </div>
</template>

<!-- <script setup>
import { onMounted, reactive } from "vue";
// import Chart from "chart.js/auto";

// Quick stats cards data
const statsCards = reactive([
  { title: "Total Alerts", value: 125, icon: "bi bi-exclamation-triangle-fill" },
  { title: "Active Logs", value: 342, icon: "bi bi-box-arrow-in-down-right" },
  { title: "Users", value: 12, icon: "bi bi-people-fill" },
  { title: "System Status", value: "Healthy", icon: "bi bi-cpu-fill" },
]);

// Recent alerts mock data
const recentAlerts = reactive([
  { type: "SQL Injection", severity: "High", ip: "192.168.1.10", time: "2025-10-01 14:30" },
  { type: "Brute Force", severity: "Medium", ip: "192.168.1.15", time: "2025-10-01 13:50" },
  { type: "Malware", severity: "High", ip: "10.0.0.8", time: "2025-10-01 12:45" },
  { type: "Port Scan", severity: "Low", ip: "172.16.0.2", time: "2025-10-01 12:20" },
]);

// Severity color helper
function severityClass(severity) {
  if (severity === "High") return "badge bg-danger";
  if (severity === "Medium") return "badge bg-warning text-dark";
  if (severity === "Low") return "badge bg-success";
  return "badge bg-secondary";
}

// Charts
onMounted(() => {
  // Alerts chart
  new Chart(document.getElementById("alertsChart"), {
    type: "doughnut",
    data: {
      labels: ["High", "Medium", "Low"],
      datasets: [
        {
          data: [45, 55, 25],
          backgroundColor: ["#dc3545", "#ffc107", "#198754"],
        },
      ],
    },
  });

  // Logs chart
  new Chart(document.getElementById("logsChart"), {
    type: "line",
    data: {
      labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
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
</script> -->
