<template>
  <div 
    class="modal fade" 
    :id="id" 
    tabindex="-1" 
    aria-hidden="true"
    ref="modalRef"
  >
    <div class="modal-dialog modal-xl">
      <div class="modal-content">

        <!-- Header -->
        <div class="modal-header">
          <h5 class="modal-title">{{ title }}</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>

        <!-- Body -->
        <div class="modal-body">
          <slot name="body"></slot>
        </div>

        <!-- Footer -->
        <div class="modal-footer">
          <slot name="footer">
        </slot>
        <!-- <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Close</button> -->
        </div>

      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";

const props = defineProps({
  id: { type: String, required: true },
  title: { type: String, default: "Modal Title" }
});

const modalRef = ref(null);
let modalInstance = null;

onMounted(() => {
  modalInstance = new bootstrap.Modal(modalRef.value);
});

const open = () => modalInstance.show();
const close = () => modalInstance.hide();

defineExpose({ open, close });
</script>
