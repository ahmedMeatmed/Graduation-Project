<template>
  <div class="container my-5">
    <!-- <h1 class="fw-bold text-center mb-4">My Profile</h1> -->

    <div class="row justify-content-center">
      <div class="col-md-6">

        <!-- Profile Card -->
        <div class="card shadow p-4 text-center">
          <!-- Avatar -->
                <i class="bi bi-person-fill" style="font-size: 72px;"></i>


          <!-- User Info -->
          <h4 class="fw-semibold">{{ profile.name }}</h4>
          <p class="text-muted mb-3">{{ profile.role }}</p>

          <!-- Profile Form -->
          <form @submit.prevent="updateProfile">
            <!-- Name -->
            <div class="mb-3 text-start">
              <label class="form-label">Full Name</label>
              <input v-model="profile.name" type="text" class="form-control" placeholder="Enter your name">
            </div>

            <!-- <div class="spinner-border" role="status">
              <span class="visually-hidden">Loading...</span>
            </div> -->

                <!--  -->

            <!-- Password -->
            <!-- <div class="mb-3 text-start">
              <label class="form-label">Change Password</label>
              <input v-model="profile.password" type="password" class="form-control" placeholder="New Password">
            </div> -->

            <!-- Confirm -->
            <!-- <div class="mb-3 text-start">
              <label class="form-label">Confirm Password</label>
              <input v-model="profile.confirmPassword" type="password" class="form-control" placeholder="Confirm Password">
            </div> -->

            <!-- Update Button -->
            <div class="d-grid">
              <button type="submit" class="btn btn-primary">Update Profile</button>
            </div>
          </form>
        </div>

      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive } from "vue";
import { useDataStore } from "../stores/dataStore";
const data = useDataStore();

// Mock profile data (can later be fetched from backend)
const profile = reactive({
  name: data.user.username,
  role: data.user.role,
});



</script>
