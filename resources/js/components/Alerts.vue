<template>
        <table class="table table-striped border m-0 p-0">
            <thead>
                <tr>
                   
                        <th>AlertID</th>
                        <th>LogID</th>
                        <th>Message</th>
                        <th>AttackType</th>
                        <th>SourceIP</th>
                        <th>DestinationIP</th>
                        <th>AssignedTo</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="alert in data.alerts" :key="alert.AlertID">
                     
                    <td>{{ alert.AlertID }}</td>
                    <td>{{ alert.LogID }}</td>
                    <td><router-link :to="singleAlert(alert.AlertID)">{{ alert.Message }}</router-link></td>
                    <td>{{ alert.AttackType }}</td>
                    <td>{{ alert.SourceIP }}</td>
                    <td>{{ alert.DestinationIP }}</td>
                    <td>{{ alert.AssignedTo }}</td>
                    <td>{{ alert.Severity }}</td>
                    <td>{{ alert.Status }}</td>
                    <td>{{ alert.Timestamp }}</td>

                </tr>
            </tbody>
        </table>
</template>
<script setup>
import { useDataStore } from '../stores/dataStore';
useDataStore().FetchAlerts();
const data = useDataStore();

const singleAlert = (alertId)=>{
    return `/alerts/${alertId}`;
}
</script>