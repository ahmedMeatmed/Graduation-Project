<template>
        <table class="table table-striped border m-0 p-0">
            <thead>
                <tr>
                   
                        <th class="text-center border">AlertID</th>
                        <th class="text-center border">LogID</th>
                        <th class="text-center border">Message</th>
                        <th class="text-center border">AttackType</th>
                        <th class="text-center border">SourceIP</th>
                        <th class="text-center border">DestinationIP</th>
                        <!-- <th class="text-center border">AssignedTo</th> -->
                        <th class="text-center border">Severity</th>
                        <th class="text-center border">Status</th>
                        <th class="text-center border">Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="alert in data.alerts" :key="alert.AlertID">
                     
                    <td class="text-center border">{{ alert.AlertID }}</td>
                    <td class="text-center border"><router-link :to="singleLog(alert.LogID)">{{ alert.LogID }}</router-link></td>
                    <td class="text-center border"><router-link :to="singleAlert(alert.AlertID)">{{ alert.Message }}</router-link></td>
                    <td class="text-center border">{{ alert.AttackType }}</td>
                    <td class="text-center border">{{ alert.SourceIP }}</td>
                    <td class="text-center border">{{ alert.DestinationIP }}</td>
                    <!-- <td class="text-center border">{{ alert.AssignedTo }}</td> -->
                    <td class="text-center border">{{ alert.Severity }}</td>
                    <td class="text-center border">{{ alert.Status }}</td>
                    <td class="text-center border">{{ alert.Timestamp }}</td>

                </tr>
            </tbody>
        </table>
</template>
<script setup>
import { useDataStore } from '../stores/dataStore';
// useDataStore().FetchAlerts();
const data = useDataStore();

const singleAlert = (alertId)=>{
    return `/alerts/${alertId}`;
}

const singleLog = (logId)=>{
    return `/logs/${logId}`;
}
</script>