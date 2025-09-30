<template>
    <div class="container-fluid m-0 p-0">
        <div class="row g-0">
            <div class="col-2">
                <side-bar />
            </div>
            <div class="col-10">
                <router-view />
            </div>
        </div>
    </div>
</template>
<script setup>
import SideBar from "..\\components/SideBar.vue";
</script>