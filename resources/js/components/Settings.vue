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
      
            <button @click="createSignature" class="btn btn-success btn-sm m-1"><b>Create Signature</b></button>
            
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
      <template #body>
         <form @submit.prevent="storeSignature">
            <div class="mb-3 text-start">
              <label class="form-label">engine</label>
              <input v-model="newSignature.engine" name="engine" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">attackName</label>
              <input v-model="newSignature.attackName" name="attackName" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">ruleText</label>
              <input v-model="newSignature.ruleText" name="ruleText" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">protocol</label>
              <input v-model="newSignature.protocol" protocol type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">srcIp</label>
              <input v-model="newSignature.srcIp" name="srcIp" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">srcPort</label>
              <input v-model="newSignature.srcPort" name="srcPort" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">direction</label>
              <input v-model="newSignature.direction" name="direction" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">destIp</label>
              <input v-model="newSignature.destIp" name="destIp" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">destPort</label>
              <input v-model="newSignature.destPort" name="destPort" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">flow</label>
              <input v-model="newSignature.flow" name="flow" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">http</label>
              <input v-model="newSignature.http" name="http" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">tls</label>
              <input v-model="newSignature.tls" name="tls" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">contentPattern</label>
              <input v-model="newSignature.contentPattern" name="contentPattern" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">sid</label>
              <input v-model="newSignature.sid"  name="sid" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">rev</label>
              <input v-model="newSignature.rev" name="rev" type="text" class="form-control" placeholder="Enter your name">
            </div>
            <button type="submit" class="btn btn-primary">Save</button>
            </form>
      </template>
      <template #footer>
      </template>
    </Modal>
    <Modal ref="showUsers" id="showUsers" title="show Users">

    </Modal>
    <Modal ref="showSignatures" id="showSignatures" title="showSignatures" >
      <template #body>
              <div class="mb-3">
                <form @submit.prevent="searchSignature">
                  <input type="search" v-model="signature.attackName" class="form-control d-inline" style="width: 95%;" placeholder="Search by Attack Name">
                <button type="submit"><i class="bi bi-search p-2 fs-5 m-2" style="cursor: pointer;"></i></button>
                </form>
                <div :style="backToAllSignatures" >
                  <!-- <i 
                    class="bi bi-arrow-left-circle-fill m-1 text-center fs-3" 
                    ></i> -->
                    <span 
                    style="cursor: pointer;"
                    @click="viewSignatures"
                    class="text-primary"
                    >BackToAllSignatures</span>
                </div>
                
            </div>
        <table class="table table-striped border">
        <thead>
          <th class="border p-1 text-center">#</th>
          <th class="border p-1 text-center">engine</th>
          <th class="border p-1 text-center">attackName</th>
          <th class="border p-1 text-center">protocol</th>
          <th class="border p-1 text-center">srcIp</th>
          <th class="border p-1 text-center">srcPort</th>
          <!-- <th class="border p-1 text-center">direction</th> -->
          <th class="border p-1 text-center">destIp</th>
          <!-- <th class="border p-1 text-center">destPort</th> -->
          <!-- <th class="border p-1 text-center">view</th> -->
        </thead>
        <tbody>
          <tr v-for="(signature,index) in data.signatures" :key="index">
            <td class="border p-1 text-center">{{ signature.signId }}</td>
            <td class="border p-1 text-center">{{ signature.engine }}</td>
            <td class="border p-1 text-center">
              <!-- <router-link :to="singleSignature(signature.signId)" @click="showSignatures.value.close()">
                {{ signature.attackName }}
              </router-link> -->
              <a :href="singleSignature(signature.signId)">{{ signature.attackName }}</a>
            </td>
            <td class="border p-1 text-center">{{ signature.protocol }}</td>
            <td class="border p-1 text-center">{{ signature.srcIp }}</td>
            <td class="border p-1 text-center">{{ signature.srcPort }}</td>
            <!-- <td class="border p-1 text-center">{{ signature.direction }}</td> -->
            <td class="border p-1 text-center">{{ signature.destIp }}</td>
            <!-- <td class="border p-1 text-center">{{ signature.destPort }}</td> -->
            <!-- <td class="border p-1 text-center"><button class="btn btn-info">View</button></td> -->
          </tr>
        </tbody>
      </table>
      </template>
      <template #footer>
        <i 
        class="bi bi-arrow-left-circle-fill fs-1 text-center m-auto" 
        style="cursor: pointer;" 
        @click="decrementPage"
        :style="sliderVisibility"
        ></i>
        <span :style="sliderVisibility">- {{ page }} -</span>
        <i 
        class="bi bi-arrow-right-circle-fill fs-1 text-center m-auto" 
        style="cursor: pointer;" 
        @click="incrementPage"
        :style="sliderVisibility"
        ></i>
        <span :style="signaturesNumberVisibilty" >Signatures : {{ data.signatures.length }}</span>
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
const page = ref(1);
const sliderVisibility = ref("visibility: visible;");
const signaturesNumberVisibilty = ref("visibility: hidden;");
const backToAllSignatures = ref("visibility: hidden;");


const createUser = ()=>{
  User.value.open()
}
const createSignature = ()=>{
  Signature.value.open()
}

const viewUsers =()=>{
  showUsers.value.open()
}

const incrementPage = ()=>{
  if(page.value < data.lastPage){
    page.value++
  }
  useDataStore().FetchSignatures(page.value);
}
const decrementPage = ()=>{
  if(page.value > 0 && page.value != 1){
    page.value--;
    viewSignatures;
  }
}

const viewSignatures = ()=>{
  useDataStore().FetchSignatures(page.value);
  showSignatures.value.open()
  sliderVisibility.value="visibility: visible;";
  signaturesNumberVisibilty.value = "visibility: hidden;";
  backToAllSignatures.value = "visibility: hidden;";
  signature.value.attackName = '';
}

const newUser = ref({
  userName:'',
  password:'',
  confirmPassword:'',
  role:'Admin',
});

// console.log(date.toLocaleDateString());

const date = new Date;
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
 created_at : date.toLocaleDateString(),
 })

const signature = ref({
  attackName : '',
})

const searchSignature = ()=>
{
    sliderVisibility.value="visibility: hidden;";
    signaturesNumberVisibilty.value = "visibility: visible;";
    backToAllSignatures.value = "visibility: visible;";
    data.searchSignature(signature.value.attackName);   
}

const singleSignature = (signature)=>{
  return `signatures/${signature}`;
}

const storeSignature = ()=>{
  // console.log(newSignature.value)
  data.storeSignature( newSignature.value);
}




</script>
