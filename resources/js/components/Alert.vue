<template>

    <div class="card text-center mt-2">
  <div class="card-header">
    Date : {{ data.singleAlert.Timestamp }}
  </div>
  <div class="card-body">
    <h5 class="card-title border-bottom text-left p-2">SourceIP : {{ data.singleAlert.SourceIP}} </h5>
    <h5 class="card-title border-bottom text-left p-2">DestinationIP : {{ data.singleAlert.DestinationIP}}</h5>
    <h5 class="card-title border-bottom text-left p-2">Message : {{ data.singleAlert.Message}}</h5>
    <h5 class="card-title border-bottom text-left p-2">AttackType : {{ data.singleAlert.AttackType}}</h5>
    <h5 class="card-title border-bottom text-left p-2">Severity : {{ data.singleAlert.Severity}}</h5>
    <h5 class="card-title border-bottom text-left p-2">Status : {{ data.singleAlert.Status}}</h5>
   
    <router-link to="/alerts" class="btn btn-success">Go To All Alerts</router-link>
  </div>
  <div class="card-footer text-body-secondary ">
    AssignedTo : {{ data.singleAlert.AssignedTo }}
  </div>
</div>
</template>
<script setup>
import { useRoute } from 'vue-router';
import { useDataStore } from '../stores/dataStore';

const router = useRoute();
useDataStore().FetchSingleAlert(router.params.alert)

const data = useDataStore();
</script>