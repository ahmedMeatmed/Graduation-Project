<template>
    <div class="card text-center mt-2">
  <div class="card-header">
    <!-- Date :  -->
  </div>
  <div class="card-body">
    <h5 class="card-title border-bottom text-left p-2">signId : {{ data.singleSignature.SignId }}</h5>
    <h5 class="card-title border-bottom text-left p-2">engine : {{ data.singleSignature.Engine }}</h5>
    <h5 class="card-title border-bottom text-left p-2">attackName : {{ data.singleSignature.AttackName }}</h5>
    <h5 class="card-title border-bottom text-left p-2">ruleText : {{ data.singleSignature.RuleText }}</h5>
    <h5 class="card-title border-bottom text-left p-2">protocol : {{ data.singleSignature.Protocol }}</h5>
    <h5 class="card-title border-bottom text-left p-2">srcIp : {{ data.singleSignature.SrcIp }}</h5>
    <h5 class="card-title border-bottom text-left p-2">srcPort : {{ data.singleSignature.SrcPort }}</h5>
    <h5 class="card-title border-bottom text-left p-2">direction : {{ data.singleSignature.Direction }}</h5>
    <h5 class="card-title border-bottom text-left p-2">destIp : {{ data.singleSignature.DestIp }}</h5>
    <h5 class="card-title border-bottom text-left p-2">destPort : {{ data.singleSignature.DestPort }}</h5>
    <h5 class="card-title border-bottom text-left p-2">flow : {{ data.singleSignature.Flow }}</h5>
    <h5 class="card-title border-bottom text-left p-2">http : {{ data.singleSignature.Http }}</h5>
    <h5 class="card-title border-bottom text-left p-2">tls : {{ data.singleSignature.Tls }}</h5>
    <h5 class="card-title border-bottom text-left p-2">contentPattern : {{ data.singleSignature.ContentPattern }}</h5>
    <h5 class="card-title border-bottom text-left p-2">sid : {{ data.singleSignature.Sid }}</h5>
    <h5 class="card-title border-bottom text-left p-2">rev :{{ data.singleSignature.Rev }}</h5>
    <h5 class="card-title border-bottom text-left p-2">created_at : {{ data.singleSignature.CreatedAt }}</h5>
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
