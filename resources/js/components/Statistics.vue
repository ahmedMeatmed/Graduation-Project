<template>
    <!-- Quick Stats -->
    <div class="row g-4 mb-4">
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-exclamation-triangle-fill fs-2 mb-2 text-danger"></i>
          <h5>Total Alerts</h5>
          <h3 class="fw-bold">{{ data.alerts.length }}</h3>
        </div>
      </div>
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-box-arrow-in-down-right fs-2 mb-2 text-warning"></i>
          <h5>Active Logs</h5>
          <h3 class="fw-bold">{{ data.logs.length }}</h3>
        </div>
      </div>
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-people-fill fs-2 mb-2 text-success"></i>
          <h5>Users</h5>
          <!-- <h3 class="fw-bold">{{ card.value }}</h3> -->
          <h3 class="fw-bold">123</h3>
        </div>
      </div>
      <div class="col-md-3" >
        <div class="card shadow text-center p-3">
          <i class="bi bi-cpu-fill fs-2 mb-2 text-info"></i>
          <h5>System Status</h5>
          <h3 class="fw-bold">{{ systemStatus(data.alerts.length) }}</h3>
        </div>
      </div>
    </div>
</template>
<script setup>
import { useDataStore } from '../stores/dataStore';

const data = useDataStore();

const systemStatus =(noAlerts)=>{
  if(noAlerts < 3) return "Healthy";
  if(noAlerts > 3 && noAlerts < 7) return "Medium";
  if(noAlerts > 7) return "Weak";
}



</script>