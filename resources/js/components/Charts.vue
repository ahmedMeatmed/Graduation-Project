<template>

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
    
</template>
<script setup>
import Chart from "chart.js/auto";
import { computed, onMounted} from 'vue';
import { useDataStore } from "../stores/dataStore";


const highAlert = computed(() =>
  useDataStore().alerts.filter(a => a.Severity === "High").length
);
const midAlert = computed(() =>
  useDataStore().alerts.filter(a => a.Severity === "Medium").length
);
const lowAlert = computed(() =>
  useDataStore().alerts.filter(a => a.Severity === "Low").length
);
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