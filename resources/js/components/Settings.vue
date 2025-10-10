<template>
  <div class="container my-5">
    <!-- <h1 class="fw-bold text-center mb-4">Settings</h1> -->

    <div class="row g-4">

      <!-- General Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">General Settings</h4>
            <div class="mb-3">
              <label class="form-label">Project Name</label>
              <input type="text" class="form-control" disabled value="AEGIS">
            </div>
            <div class="form-check form-switch">
              <input class="form-check-input p-2" type="checkbox" style="cursor: pointer;">
              <label class="form-check-label">Theme</label>
            </div>
        </div>
      </div>


      <!-- Logs Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Logs Settings</h4>
          <form>
            <div class="mb-3">
              <label class="form-label">Log Retention (days)</label>
              <input type="number" class="form-control">
            </div>
            <button class="btn btn-outline-primary btn-sm">
              Export Logs
            </button>
          </form>
        </div>
      </div>

      <SignatureSettings />
      <UserSettings />
    </div>
  </div>
</template>

<script setup>
import SignatureSettings from './SignatureSettings.vue';
import UserSettings from './UserSettings.vue';
</script>
