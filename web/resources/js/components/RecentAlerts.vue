<template>
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
</template>
<script setup>
import { useDataStore } from '../stores/dataStore';


const singleAlert = (alertId)=>{
  return `alerts/${alertId}`;
}



// Severity color helper
const severityClass= (severity) => {
  if (severity === "High") return "badge bg-danger";
  if (severity === "Medium") return "badge bg-warning text-dark";
  if (severity === "Low") return "badge bg-success";
  return "badge bg-secondary";
}

const recentAlerts =useDataStore().alerts.filter(a => a.Status === "New" || a.Status === "Investigating");


</script>