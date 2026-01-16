<template>
    <div class="container-fluid m-0 p-0">
      <LoadingSpinner v-if="store.loading" />
      <div v-else class="row g-0">
        <div class="col-1">
          <SideBar />
        </div>
        <div class="col-11 ps-3 m-0">
          <router-view />
        </div>
      </div>
  </div> 
</template>

<script setup>
import SideBar from "@/components/SideBar.vue"
import LoadingSpinner from "../tools/LoadingSpinner.vue";
import { useDataStore } from "@/stores/dataStore"
import { onMounted } from "vue"

const store = useDataStore()
onMounted(async()=>{
  await store.FetchUsers();
  await store.FetchLogs();
  await store.FetchAlerts();
  await store.FetchUser();
//   setInterval(() => {
//   store.FetchLogs();
//   store.FetchAlerts();
// }, 5000);

})

</script>
