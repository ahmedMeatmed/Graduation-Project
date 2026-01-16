<template>

    <div class="card text-center mt-5">
  <div class="card-header bg-info">
    <b>Date</b> : {{ data.singleAlert.Timestamp }}
  </div>
  <div class="card-body">
    <span class="card-title border-bottom text-left p-2 d-block"><b>SourceIP </b>: {{ data.singleAlert.SourceIP}} </span>
    <span class="card-title border-bottom text-left p-2 d-block"><b>DestinationIP </b>: {{ data.singleAlert.DestinationIP}}</span>
    <span class="card-title border-bottom text-left p-2 d-block"><b>Message </b>: {{ data.singleAlert.Message}}</span>
    <span class="card-title border-bottom text-left p-2 d-block"><b>AttackType </b>: {{ data.singleAlert.AttackType}}</span>
    <span class="card-title border-bottom text-left p-2 d-block"><b>Severity </b>: {{ data.singleAlert.Severity}}</span>
    <span class="card-title border-bottom text-left p-2 d-block"><b>Status </b>: {{ data.singleAlert.Status}}</span>
    <div class="mb-3 w-25">
      <p class="form-label text-left"><b>Assign To</b></p>
      <select name="role" id="role" v-model="assignedTo" class="form-select dropdown" style="cursor: pointer;" required>              
         <option disabled value=""><b>-- Select User --</b></option>
        <option  v-for="user in data.users" :value="user.userName" :key="user.userId" >{{ user.userName }}</option>
      </select>
    </div>
    <button class="btn btn-dark m-1 disabled" v-if="data.singleAlert.Status == 'Resolved'">Resolved</button>
    <button class="btn btn-dark bg-primary m-1" v-else @click="resolving" :class="status.class">{{ status.content }}</button>
    
    
    <button class="btn btn-warning m-1 bg-dark disabled text-white" v-if="data.singleAlert.Status == 'Investigating'">Investigating</button>
    <button class="btn btn-warning m-1" v-else @click="investigating" :class="status.investigateClass">{{ status.investgateContent }}</button>

    <!-- <router-link to="/alerts" class="btn btn-primary">Go To All Alerts</router-link> -->
  </div>
  <div class="card-footer">
    <b>AssignedTo</b> : {{ data.singleAlert.AssignedTo }}
  </div>
</div>
</template>
<script setup>
import { useRoute } from 'vue-router';
import { useDataStore } from '../stores/dataStore';
import { onMounted, ref } from 'vue';

const router = useRoute();
const data = useDataStore();

const status = ref({
  content:"Resolve",
  class:"",
  investgateContent:"Investigate",
  investigateClass:"",
  state:""
});

const investigating = ()=>{
  status.value.investgateContent = "Investigating";
  status.value.investigateClass ="bg-dark disabled text-white";
  status.value.state = "Investigating";
  assign();
}

const resolving = ()=>{
  status.value.content = "Resolved";
  status.value.class ="bg-dark disabled";
  status.value.state = "Resolved";
  assign();
}

const assignedTo = ref(data.singleAlert.AssignedTo );
const assign = ()=>{
  // console.log(router.params.alert , status.value.state , assignedTo.value);
  data.updateAlertStatus(router.params.alert , status.value.state , assignedTo.value);
}

onMounted(()=>{
  useDataStore().FetchSingleAlert(router.params.alert)
})
</script>