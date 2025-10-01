<template>
    <div class="card text-center mt-2">
  <div class="card-header">
    Date : {{ data.singleLog.Timestamp }}
  </div>
  <div class="card-body">
    <h5 class="card-title border-bottom text-left p-2">SourceIP : {{ data.singleLog.SourceIP}} </h5>
    <h5 class="card-title border-bottom text-left p-2">DestinationIP : {{ data.singleLog.DestinationIP}}</h5>
    <h5 class="card-title border-bottom text-left p-2">PacketSize : {{ data.singleLog.PacketSize}}</h5>
    <h5 class="card-title border-bottom text-left p-2">IsMalicious : {{ data.singleLog.IsMalicious}}</h5>
    <h5 class="card-title border-bottom text-left p-2">Protocol : {{ data.singleLog.Protocol}}</h5>
    <h5 class="card-title border-bottom text-left p-2">SrcPort : {{ data.singleLog.SrcPort}}</h5>
    <h5 class="card-title border-bottom text-left p-2">DestPort : {{ data.singleLog.DestPort}}</h5>
    <h5 class="card-title border-bottom text-left p-2">PayloadSize : {{ data.singleLog.PayloadSize}}</h5>
    <h5 class="card-title border-bottom text-left p-2">TcpFlags : {{ data.singleLog.TcpFlags}}</h5>
    <h5 class="card-title border-bottom text-left p-2">FlowDirection : {{ data.singleLog.FlowDirection}}</h5>
    <h5 class="card-title border-bottom text-left p-2">PacketCount : {{ data.singleLog.PacketCount}}</h5>
    <h5 class="card-title border-bottom text-left p-2">MatchedSignatureId : {{ data.singleLog.MatchedSignatureId}}</h5>
 
    <router-link to="/logs" class="btn btn-success">Go To All Logs</router-link>
  </div>
  <div class="card-footer text-body-secondary ">
    Duration : {{ data.singleLog.Duration }}
  </div>
</div>
</template>
<script setup>
import { useRoute } from 'vue-router';
import { useDataStore } from '../stores/dataStore';
const router = useRoute();
useDataStore().FetchSingleLog(router.params.log)
const data = useDataStore();
</script>
