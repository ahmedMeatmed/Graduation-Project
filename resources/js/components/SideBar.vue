<template>
    <div class="d-flex flex-column flex-shrink-0 bg-body-tertiary border position-fixed m-0 p-0" >
        <router-link to="/dashboard" class="d-block link-body-emphasis text-decoration-none border-bottom m-0" data-bs-toggle="tooltip"
            data-bs-placement="right" data-bs-original-title="Icon-only">
            <!-- <h3 class="text-center ">IDS</h3> -->
            <img src="..\\imgs/logo.png" alt="Logo" class="m-auto" style="border-radius: 50%;" >

            <span class="visually-hidden">Icon-only</span>
        </router-link>
        <ul class="nav nav-pills nav-flush flex-column mb-auto text-center">
            <li class="nav-item">
                <router-link  to="/dashboard" exact-active-class="active" class="nav-link py-3 border-bottom rounded-0" aria-current="page"
                    data-bs-toggle="tooltip" data-bs-placement="right" aria-label="Home" data-bs-original-title="Home">
                    <i class="bi bi-speedometer2 m-1"></i>
                    <span>Dashboard</span>
                </router-link>
            </li>
            <li>
                <router-link to="/logs" active-class="active" class="nav-link py-3 border-bottom rounded-0" data-bs-toggle="tooltip"
                    data-bs-placement="right" aria-label="Dashboard" data-bs-original-title="Dashboard">
                    <i class="bi bi-box-arrow-in-down-right m-1"></i>
                    <span>Logs</span>
                </router-link>
            </li>
            <li>
                <router-link to="/alerts" active-class="active" class="nav-link py-3 border-bottom rounded-0" data-bs-toggle="tooltip"
                    data-bs-placement="right" aria-label="Orders" data-bs-original-title="Orders">
                    <i class="bi bi-exclamation-octagon-fill fs-4"></i>
                    <i v-if="notifications > 0"
                    class="bi bi-circle-fill text-danger m-1 position-absolute">
                        <!-- <span class="text-warning"><b>{{ notifications }}</b></span> -->
                    </i>
                    <h6>Alerts</h6>
                </router-link>
            </li>
            <li>
                <router-link to="/about" active-class="active" class="nav-link py-3 border-bottom rounded-0" data-bs-toggle="tooltip"
                    data-bs-placement="right" aria-label="Products" data-bs-original-title="Products">
                  <i class="bi bi-info-circle"></i>
                  <h6>About Us</h6>
                </router-link>
            </li>
            <li>
                <router-link to="/contact" active-class="active" class="nav-link py-3 border-bottom rounded-0" data-bs-toggle="tooltip"
                    data-bs-placement="right" aria-label="Customers" data-bs-original-title="Customers">
                    <i class="bi bi-telephone-fill"></i>
                    <h6>Contact Us</h6>
                </router-link>
            </li>
               <li>
                <router-link to="/settings" active-class="active" class="nav-link py-3 border-bottom rounded-0" data-bs-toggle="tooltip"
                    data-bs-placement="right" aria-label="Customers" data-bs-original-title="Customers">
                    <i class="bi bi-gear-fill"></i>
                    <h6>Settings</h6>
                </router-link>
            </li>
            <li>
                <div class="dropdown ">
            <a href="#"
                class="d-flex align-items-center justify-content-center p-3 link-body-emphasis text-decoration-none dropdown-toggle"
                data-bs-toggle="dropdown" aria-expanded="false">
                <!-- <img src="" alt="mdo" width="24" height="24" class="rounded-circle" /> -->
                <i class="bi bi-person-fill fs-4"></i>
            </a>
            <ul class="dropdown-menu text-small shadow" style="">
                <!-- <li><router-link to="/settings" class="dropdown-item">Settings</router-link></li> -->
                <li><router-link to="/profile" class="dropdown-item">Profile </router-link></li>
                <li>
                    <hr class="dropdown-divider" />
                </li>
                <li><a class="dropdown-item" @click="logoutUser" style="cursor: pointer;">Sign out</a></li>
            </ul>
        </div>
            </li>
        </ul>
        
    </div>
</template>
<script setup>
import { computed } from 'vue';
import { useDataStore } from '../stores/dataStore';
import { useRouter } from 'vue-router';
const router = useRouter();

const data =useDataStore();
let notifications = computed(()=>data.alerts.length);
const logoutUser = async ()=>{
    await data.logout();
    router.push('/login');
}

</script>