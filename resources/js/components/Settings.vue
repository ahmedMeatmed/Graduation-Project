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

      <!-- User Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">User Settings</h4>
           <button class="btn btn-success btn-sm m-1" @click="createUser()"><b>Create User</b></button>
            <button class="btn btn-info btn-sm m-1" @click="viewUsers"><b>Show Users</b></button>
        </div>
      </div>

      <!-- Signature Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Signature Settings</h4>
      
            <button class="btn btn-success btn-sm m-1" @click="createSignature"><b>Create Signature</b></button>
            <button class="btn btn-info btn-sm m-1" @click="viewSignatures"><b>Show Signatures</b></button>
          
        </div>
      </div>
    </div>

    <Modal ref="User" id="createUser" title="Create User">
      <template #body>
        <form @submit.prevent="">
          <div class="mb-3">
            <label class="form-label"><b>user name</b></label>
            <input v-model="newUser.userName" type="text" class="form-control" required>
          </div>
              <div class="mb-3">
            <label class="form-label"><b>Role</b></label>
            <!-- <input v-model="newUser.role" type="text" class="form-control" required> -->
            <select name="role" id="role" v-model="newUser.role" class="form-control dropdown" style="cursor: pointer;" required>
              <option value="1">Admin</option>
              <option value="0">Analyst</option>
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label"><b>password</b></label>
            <input v-model="newUser.password" type="password" class="form-control" required>
          </div>
             <div class="mb-3">
            <label class="form-label"><b>confirm password</b></label>
            <input v-model="newUser.confirmPassword" type="password" class="form-control" required>
          </div>
        </form>
      </template>
        <template #footer>
            <button type="button" class="btn btn-primary">Save</button>

      </template>
    </Modal>
    <Modal ref="Signature" id="createSignature" title="Create Signature">
      <template #body></template>
      <template #footer>
            <button type="button" class="btn btn-primary">Save</button>

      </template>
    </Modal>
    <Modal ref="showUsers" id="showUsers" title="show Users">

    </Modal>
    <Modal ref="showSignatures" id="showSignatures" title="showSignatures" >
      <template #body>
              <div class="mb-3">
            <input type="search" class="form-control" >
          </div>
        <table class="table table-striped border">
        <thead>
          <th class="border p-1 text-center">engine</th>
          <th class="border p-1 text-center">attackName</th>
          <th class="border p-1 text-center">protocol</th>
          <th class="border p-1 text-center">srcIp</th>
          <th class="border p-1 text-center">srcPort</th>
          <th class="border p-1 text-center">direction</th>
          <th class="border p-1 text-center">destIp</th>
          <th class="border p-1 text-center">destPort</th>
          <th class="border p-1 text-center">created_at</th>
        </thead>
        <tbody>
          <tr>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
            <td class="border p-1 text-center">123</td>
          </tr>
        </tbody>
      </table>
      </template>
      <template #footer>
        <i 
        class="bi bi-arrow-left-circle-fill fs-1 text-center m-auto" 
        style="cursor: pointer;" 
        @click="decrementPage"
        ></i>
        <span >-- {{ page }} --</span>
        <i 
        class="bi bi-arrow-right-circle-fill fs-1 text-center m-auto" 
        style="cursor: pointer;" 
        @click="incrementPage"
        ></i>
      </template>
    </Modal>

   
  </div>
</template>

<script setup>
import { ref } from "vue";
import Modal from "../tools/Modal.vue";
import { useDataStore } from "../stores/dataStore";
const data = useDataStore();
const User = ref(null);
const Signature = ref(null);
const showUsers = ref(null);
const showSignatures = ref(null);

const createUser = ()=>{
  User.value.open()
}
const createSignature = ()=>{
  Signature.value.open()
}

const viewUsers =()=>{
  showUsers.value.open()
}

const page = ref(1);
const incrementPage = ()=>{
  if(page < data.lastPage)
      page.value++
}
const decrementPage = ()=>{
  if(page > 0)
      page.value--
}

const viewSignatures = ()=>{
  useDataStore().FetchSignatures(page);
  showSignatures.value.open()
  
}

const newUser = ref({
  userName:'',
  password:'',
  confirmPassword:'',
  role:'Admin',
});

const newSignature = ref({
engine    :'', 
attackName:'',
ruleText  :'',
protocol  :'',
srcIp     :'',
srcPort   :'',
direction :'',
destIp    :'',
destPort  :'',
flow      :'',  
http      :'',
tls       :'',
contentPattern:'',
sid       :'',
rev       :'',
})



</script>
