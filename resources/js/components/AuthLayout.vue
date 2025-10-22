<template>
  <div class="container-fluid m-0 p-0">
    <div class="row g-0">
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
import { useDataStore } from "@/stores/dataStore"

const store = useDataStore()
store.FetchLogs()
store.FetchAlerts()
</script>
