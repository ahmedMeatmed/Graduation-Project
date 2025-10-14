import './bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
// import 'bootstrap/dist/js/bootstrap.bundle.min.js';
import { createApp } from 'vue';
import { createWebHistory, createRouter  } from "vue-router";
import { createPinia } from 'pinia';
import routes from './router/routes';
import App from './components/App.vue'
import Login from './components/LoginPage.vue';




const pinia = createPinia();
const router = createRouter({
    
    history:createWebHistory(),
    routes
})

const app = createApp(App);


app.use(pinia);
app.use(router);
app.mount('#app');