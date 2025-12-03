<template>
    <div
    class="position-fixed top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center bg-light bg-opacity-0"
    style="z-index:2000;"
  >
    <div class="spinner-multi"></div>
  </div>
</template>
<style scoped>
.spinner-multi {
  width: 4rem;
  height: 4rem;
  border: 0.5rem solid transparent;
  border-top-color: #ff4b1f;
  border-right-color: #ff9068;
  border-bottom-color: #1fddff;
  border-left-color: #00c9ff;
  border-radius: 50%;
  animation: spin 1s linear infinite, hue 4s linear infinite;
}

@keyframes spin {
  100% {
    transform: rotate(360deg);
  }
}

@keyframes hue {
  100% {
    filter: hue-rotate(360deg);
  }
}
</style>