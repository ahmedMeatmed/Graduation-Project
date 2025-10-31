<template>
   <div class="container my-5">
                  <Statistics />
                  <Charts />
                  <RecentAlerts />
    </div>
</template>

<script setup>
import RecentAlerts from './RecentAlerts.vue';
import Charts from './Charts.vue';
import Statistics from './Statistics.vue';
</script>
