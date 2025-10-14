

<template>
  <div class="login-page d-flex align-items-center justify-content-center vh-100">
    <div class="card p-4 shadow-lg login-card">
      <div class="text-center mb-4">
        <img :src="logoUrl" alt="AEGIS Logo" class="img-fluid logo-img m-auto">
        <!-- <h4 class="mt-3 text-secondary">Intelligent Defense System</h4> -->
      </div>

      <form @submit.prevent="handleLogin">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input 
            type="text" 
            class="form-control" 
            id="username" 
            v-model="username" 
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
            v-model="password" 
            required
            placeholder="Enter your password"
          >
        </div>
        
        <div v-if="loginError" class="alert alert-danger" role="alert">
          {{ loginError }}
        </div>

        <button type="submit" class="btn btn-primary w-100 btn-lg">Log In</button>
      </form>

      <div class="text-center mt-3">
        <a href="#" class="text-muted small">Forgot Password?</a>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'LoginPage',
  data() {
    return {
      // **NOTE:** Replace '/path/to/your/logo.png' with the actual path 
      // where you place the 'logo.png' file in your project's assets or public folder.
      logoUrl: '..\\imgs/logo.png', // Assuming logo.png is in your public folder
      username: '',
      password: '',
      loginError: '',
    };
  },
  methods: {
    handleLogin() {
      // Simple validation for demonstration purposes
      if (this.username === 'admin' && this.password === 'password') {
        this.loginError = '';
        console.log('Login successful!');
        // In a real application, you would handle token storage, 
        // redirect the user, and make an API call here.
        alert('Login Successful!');
      } else {
        this.loginError = 'Invalid username or password. Please try again.';
      }
    },
  },
};
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