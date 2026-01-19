<template>
  <div class="container my-5">
    <div class="text-center mb-4">
      <!-- <h1 class="fw-bold">Contact Us</h1> -->
      <p class="text-muted">
        Have questions about our IDS project? Reach out to our team — we’d love to hear from you.
      </p>
    </div>

    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="card shadow p-4">
          <form>
            <!-- Name -->
            <div class="mb-3">
              <label for="name" class="form-label">Full Name</label>
              <input type="text" id="name" class="form-control" placeholder="Enter your name" required>
            </div>

            <!-- Email -->
            <div class="mb-3">
              <label for="email" class="form-label">Email Address</label>
              <input type="email" id="email" class="form-control" placeholder="Enter your email" required>
            </div>

            <!-- Message -->
            <div class="mb-3">
              <label for="message" class="form-label">Message</label>
              <textarea id="message" class="form-control" rows="5" placeholder="Type your message here..." required></textarea>
            </div>

            <!-- Submit -->
            <div class="d-grid">
              <button type="submit" class="btn btn-primary">Send Message</button>
            </div>
          </form>
        </div>
      </div>
    </div>

    <!-- Footer Info -->
    <div class="text-center mt-5">
      <p class="mb-1"><strong>Intrusion Detection System (IDS)</strong> – Graduation Project</p>
      <!-- <p class="text-muted">Team of 12 Computer Science Students | 2025</p> -->
      <div class="d-flex justify-content-center gap-3">
        <a href="#" class="text-dark fs-4"><i class="bi bi-envelope-fill"></i></a>
        <a href="#" class="text-dark fs-4"><i class="bi bi-linkedin"></i></a>
        <a href="#" class="text-dark fs-4"><i class="bi bi-github"></i></a>
      </div>
    </div>
  </div>
</template>
