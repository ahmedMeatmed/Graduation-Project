<template>

   <!-- User Settings -->
      <div class="col-md-6">
        <div class="card shadow p-4">
          <h4 class="fw-semibold mb-3">User Settings</h4>
           <button class="btn btn-success btn-sm m-1" @click="createUser()"><b>Create User</b></button>
            <button class="btn btn-info btn-sm m-1" @click="viewUsers"><b>Show Users</b></button>
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
            <select name="role" id="role" v-model="newUser.role" class="form-select dropdown" style="cursor: pointer;" required>
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

  <Modal ref="showUsers" id="showUsers" title="show Users">
    <template #body>
     <table class="table table-striped border">
        <thead>
          <th class="border p-1 text-center">Id</th>
          <th class="border p-1 text-center">User Name</th>
          <th class="border p-1 text-center">Role</th>
          <th class="border p-1 text-center">Actions</th>
          </thead>
        <tbody>
          <tr v-for="user in data.users" :key="user.userId">
            <td class="border p-1 text-center">{{user.userId}}</td>
            <td class="border p-1 text-center">{{ user.userName }}</td>
            <td class="border p-1 text-center">{{ user.role }}</td>
            <td class="border p-1 text-center">
              <button @click="editUser(user)" class="btn m-1 btn-success">Edit</button>
              <button class="btn m-1 btn-primary">Show</button>
              <button class="btn m-1 btn-danger">Delete</button>
            </td>
             </tr>
        </tbody>
      </table>
      </template>
    </Modal>
    
</template>
<script setup>
import { useDataStore } from "../stores/dataStore";
import Modal from "../tools/Modal.vue";
import { ref } from "vue";

const data = useDataStore();


const showUsers = ref(null);
const User = ref(null);


const createUser = ()=>{
  User.value.open()
  newUser.value = "";
}
const viewUsers =()=>{
  showUsers.value.open();
}
const newUser = ref({
  userName:'',
  password:'',
  confirmPassword:'',
  role:'Admin',
});

const editUser = (user)=>{
  newUser.value.userName = user.userName;
  newUser.value.role = user.role;
  User.value.open();
  showUsers.value.close();
}
</script>