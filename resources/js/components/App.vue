<template>
    <div class="container-fluid m-0 p-0">
        <div class="row g-0">
            <div class="col-1">
                <side-bar />
            </div>
            <div class="col-11 p-0 m-0">
                <router-view>
                </router-view>
                <!-- <Apperance /> -->
            </div>
        </div>
    </div>
</template>
<script setup>
import SideBar from "..\\components/SideBar.vue";
import Apperance from "..\\components/Apperance.vue";
</script>