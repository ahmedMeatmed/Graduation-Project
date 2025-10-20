<template>


  <!-- Signature Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">Signature Settings</h4>
      
            <button @click="createSignature" class="btn btn-success btn-sm m-1"><b>Create Signature</b></button>
            
            <button class="btn btn-info btn-sm m-1" @click="viewSignatures"><b>Show Signatures</b></button>
          
        </div>
      </div>


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
    
    <Modal ref="showSignatures" id="showSignatures" title="showSignatures" >
      <template #body>
              <div class="mb-3">
                <form @submit.prevent="searchSignature">
                  <input type="search" @keyup="searchSignature" v-model="signature.attackName" class="form-control d-inline" style="width: 95%;" placeholder="Search by Attack Name">
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
            <td class="border p-1 text-center">{{ signature.SignId }}</td>
            <td class="border p-1 text-center">{{ signature.Engine }}</td>
            <td class="border p-1 text-center">
              <!-- <router-link :to="singleSignature(signature.signId)" @click="showSignatures.value.close()">
                {{ signature.attackName }}
              </router-link> -->
              <a :href="singleSignature(signature.signId)">{{ signature.AttackName }}</a>
            </td>
            <td class="border p-1 text-center">{{ signature.Protocol }}</td>
            <td class="border p-1 text-center">{{ signature.SrcIp }}</td>
            <td class="border p-1 text-center">{{ signature.SrcPort }}</td>
            <!-- <td class="border p-1 text-center">{{ signature.direction }}</td> -->
            <td class="border p-1 text-center">{{ signature.DestIp }}</td>
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
</template>
<script setup>
import { useDataStore } from "../stores/dataStore";
import Modal from "../tools/Modal.vue";
import { ref } from "vue";

const data = useDataStore();

const Signature = ref(null);
const showSignatures = ref(null);
const page = ref(1);
const sliderVisibility = ref("visibility: visible;");
const signaturesNumberVisibilty = ref("visibility: hidden;");
const backToAllSignatures = ref("visibility: hidden;");



const createSignature = ()=>{
  Signature.value.open()
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