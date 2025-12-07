<template>
    <div class="card text-center mt-2">
  <div class="card-header bg-info">
   <b>Date</b>: {{ data.singleLog.Timestamp }}
  </div>
  <div class="card-body bg-success text-white">
    <span class="d-block card-title border-bottom text-left p-2"><b>SourceIP </b>: {{ data.singleLog.SourceIP}} </span>
    <span class="d-block card-title border-bottom text-left p-2"><b>DestinationIP </b>: {{ data.singleLog.DestinationIP}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>PacketSize </b>: {{ data.singleLog.PacketSize}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>IsMalicious </b>: {{ data.singleLog.IsMalicious}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>Protocol </b>: {{ data.singleLog.Protocol}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>SrcPort </b>: {{ data.singleLog.SrcPort}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>DestPort </b>: {{ data.singleLog.DestPort}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>PayloadSize </b>: {{ data.singleLog.PayloadSize}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>TcpFlags </b>: {{ data.singleLog.TcpFlags}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>FlowDirection </b>: {{ data.singleLog.FlowDirection}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>PacketCount </b>: {{ data.singleLog.PacketCount}}</span>
    <span class="d-block card-title border-bottom text-left p-2"><b>MatchedSignatureId </b>: {{ data.singleLog.MatchedSignatureId}}</span>
 
    <router-link to="/logs" class="btn btn-success">Go To All Logs</router-link>
  </div>
  <div class="card-footer text-body-secondary bg-warning ">
    <b>Duration</b> : {{ data.singleLog.Duration }}
  </div>
</div>
</template>
<script setup>
import { useRoute } from 'vue-router';
import { useDataStore } from '../stores/dataStore';
import { onMounted } from 'vue';
const route = useRoute();
const data = useDataStore();
onMounted(()=>{
  data.FetchSingleLog(route.params.log)

})
</script>
