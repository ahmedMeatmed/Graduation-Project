

<template>
  <div class="login-page d-flex align-items-center justify-content-center vh-100">
    <div class="card p-4 shadow-lg login-card">
      <div class="text-center mb-4">
        <img src="..\\imgs/logo.png" alt="AEGIS Logo" class="img-fluid logo-img m-auto">
        <h4 class="mt-3 text-secondary">Intelligent Defense System</h4>
      </div>

      <form @submit.prevent="loginUser">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input 
            type="text" 
            class="form-control" 
            id="username" 
            v-model="credentials.username"
            required
            placeholder="Enter your username"
          >
        </div>
        <div class="mb-4">
          <label for="password" class="form-label">Password</label>
          <input 
            type="password" 
            class="form-control" 
            id="password" 
            v-model="credentials.password"
            required
            placeholder="Enter your password"
          >
        </div>

        <button type="submit" class="btn btn-primary w-100 btn-lg">Log In</button>
      </form>
    </div>
  </div>
</template>

<script setup>

import { ref } from 'vue';
import { useRouter } from 'vue-router';
const credentials = ref({
  username: '',
  password: ''
});

    const loginUser = async ()=>{
        console.log(credentials);
        await axios.post('http://127.0.0.1:8000/api/login',credentials.value)
        .then((response)=>{
            console.log(response)

            localStorage.setItem('token', response.data.data.token);

            useRouter().push('/dashboard');
        })
        .catch((error)=>{

            console.error("Login failed:", error);
            
        });
    }

</script>

<style scoped>
.login-page {
  /* Set a nice background color for the full page */
  background-color: #f8f9fa; /* Light gray background */
}

.login-card {
  max-width: 400px; /* Limit the card width */
  width: 100%; /* Make sure it's responsive */
  border-radius: 10px; /* Rounded corners for the card */
  border: none;
}

.logo-img {
  max-width: 150px; /* Control the size of the logo */
  height: auto;
}

/* Custom button styling (optional, but a nice touch) */
.btn-primary {
    background-color: #0d6efd; /* Use the default Bootstrap primary color */
    border-color: #0d6efd;
    transition: background-color 0.3s ease;
}

.btn-primary:hover {
    background-color: #0b5ed7;
    border-color: #0a58ca;
}
</style>