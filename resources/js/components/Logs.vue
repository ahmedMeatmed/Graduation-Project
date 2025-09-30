<template>
    <table class="table table-striped border m-0 p-0">
        <thead>
            <tr>
                <th>SourceIP</th>
                <th>DestinationIP</th>
                <th>PacketSize</th>
                <th>IsMalicious</th>
                <th>Protocol</th>
                <th>SrcPort</th>
                <th>DestPort</th>
                <th>PayloadSize</th>
                <th>TcpFlags</th>
                <th>FlowDirection</th>
                <th>PacketCount</th>
                <th>Duration</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="log in logs" :key="log.LogID">
                <td>{{ log.SourceIP }}</td><td>{{ log.DestinationIP }}</td><td>{{ log.PacketSize }}</td>
                <td>{{ log.IsMalicious }}</td><td>{{ log.Protocol }}</td><td>{{ log.SrcPort }}</td>
                <td>{{ log.DestPort }}</td><td>{{ log.PayloadSize }}</td><td>{{ log.TcpFlags }}</td>
                <td>{{ log.FlowDirection }}</td><td>{{ log.PacketCount }}</td><td>{{ log.Duration }}</td>
                <td>{{ log.MatchedSignatureId}}</td><td>{{ log.Timestamp }}</td>
            </tr>
        </tbody>
    </table>
</template>
<script setup>
import { onMounted } from "vue";
import { useDataStore } from "../stores/dataStore";
import { storeToRefs } from "pinia";

const dataStore = useDataStore();
const { logs } = storeToRefs(dataStore);

console.log(logs);

onMounted(() => {
  dataStore.FetchLogs();
});
</script>