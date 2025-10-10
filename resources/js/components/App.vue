<template>
    <div class="container-fluid m-0 p-0">
        <div class="row g-0">
            <div class="col-1 ">
                <side-bar />
            </div>
            <div class="col-11 ps-3 m-0">
                <router-view>
                </router-view>
            </div>
        </div>
    </div>
</template>
<script setup>
import { useDataStore } from "../stores/dataStore";
import SideBar from "..\\components/SideBar.vue";

useDataStore().FetchLogs();
useDataStore().FetchAlerts();
</script>