<template>
    <table class="table table-striped border m-0 p-0">
        <thead>
            <tr class="text-center">
                <th class="border-end">SourceIP</th>
                <th class="border-end">DestinationIP</th>
                <!-- <th class="border-end">PacketSize</th> -->
                <!-- <th class="border-end">IsMalicious</th> -->
                <th class="border-end">Protocol</th>
                <th class="border-end">SrcPort</th>
                <th class="border-end">DestPort</th>
                <th class="border-end">PayloadSize</th>
                <th class="border-end">TcpFlags</th>
                <th class="border-end">FlowDirection</th>
                <!-- <th class="border-end">PacketCount</th> -->
                <!-- <th class="border-end">Duration</th> -->
                <th class="border-end">MatchedSign</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
            
                <tr 
                v-for="log in data.logs" :key="log.LogID"
                class="p-0 m-0 text-center lh-1">
                    
                        <td class="border-end">
                            <router-link :to=singleLog(log.LogID)>{{ log.SourceIP }}</router-link>
                        </td>
                        <td class="border-end">{{ log.DestinationIP }}</td>
                        <!-- <td class="border-end">{{ log.PacketSize }}</td> -->
                        <!-- <td class="border-end">{{ log.IsMalicious }}</td> -->
                        <td class="border-end">{{ log.Protocol }}</td>
                        <td class="border-end">{{ log.SrcPort }}</td>
                        <td class="border-end">{{ log.DestPort }}</td>
                        <td class="border-end">{{ log.PayloadSize }}</td>
                        <td class="border-end">{{ log.TcpFlags }}</td>
                        <td class="border-end">{{ log.FlowDirection }}</td>
                        <!-- <td class="border-end">{{ log.PacketCount }}</td> -->
                        <!-- <td class="border-end">{{ log.Duration }}</td> -->
                        <td class="border-end">{{ log.MatchedSignatureId}}</td>
                        <td>{{ log.Timestamp }}</td>
                    </tr>
                
        </tbody>
    </table>
</template>
<script setup>
import { onMounted, ref } from "vue";
import { useDataStore } from "../stores/dataStore";
const data = useDataStore();
useDataStore().FetchLogs();

const singleLog = (LogID)=>{
return `logs/${LogID}`;
}
</script>