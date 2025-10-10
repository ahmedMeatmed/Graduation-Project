<template>
    <div class="card text-center mt-2">
  <div class="card-header">
    <!-- Date :  -->
  </div>
  <div class="card-body">
    <h5 class="card-title border-bottom text-left p-2">signId : {{ data.singleSignature.signId }}</h5>
    <h5 class="card-title border-bottom text-left p-2">engine : {{ data.singleSignature.engine }}</h5>
    <h5 class="card-title border-bottom text-left p-2">attackName : {{ data.singleSignature.attackName }}</h5>
    <h5 class="card-title border-bottom text-left p-2">ruleText : {{ data.singleSignature.ruleText }}</h5>
    <h5 class="card-title border-bottom text-left p-2">protocol : {{ data.singleSignature.protocol }}</h5>
    <h5 class="card-title border-bottom text-left p-2">srcIp : {{ data.singleSignature.srcIp }}</h5>
    <h5 class="card-title border-bottom text-left p-2">srcPort : {{ data.singleSignature.srcPort }}</h5>
    <h5 class="card-title border-bottom text-left p-2">direction : {{ data.singleSignature.direction }}</h5>
    <h5 class="card-title border-bottom text-left p-2">destIp : {{ data.singleSignature.destIp }}</h5>
    <h5 class="card-title border-bottom text-left p-2">destPort : {{ data.singleSignature.destPort }}</h5>
    <h5 class="card-title border-bottom text-left p-2">flow : {{ data.singleSignature.flow }}</h5>
    <h5 class="card-title border-bottom text-left p-2">http : {{ data.singleSignature.http }}</h5>
    <h5 class="card-title border-bottom text-left p-2">tls : {{ data.singleSignature.tls }}</h5>
    <h5 class="card-title border-bottom text-left p-2">contentPattern : {{ data.singleSignature.contentPattern }}</h5>
    <h5 class="card-title border-bottom text-left p-2">sid : {{ data.singleSignature.sid }}</h5>
    <h5 class="card-title border-bottom text-left p-2">rev :{{ data.singleSignature.rev }}</h5>
    <h5 class="card-title border-bottom text-left p-2">created_at : {{ data.singleSignature.created_at }}</h5>
  </div>
  <div class="card-footer text-body-secondary ">
    <!-- Duration :  -->
  </div>
</div>
</template>
<script setup>
import { useRoute } from 'vue-router';
import { useDataStore } from '../stores/dataStore';
const router = useRoute();
useDataStore().FetchSingleSignature(router.params.signature)
const data = useDataStore();
</script>
