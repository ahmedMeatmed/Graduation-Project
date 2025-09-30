import './bootstrap';
import { createApp } from 'vue';
import { createWebHistory, createRouter  } from "vue-router";
import { createPinia } from 'pinia';
import routes from './router/routes';
import App from './components/App.vue'

// import ExampleComponent from './components/ExampleComponent.vue';



const pinia = createPinia();

// const router = createRouter([
//     history:createWebHistory(),
//     routes,
// ]);

const router = createRouter({
    
    history:createWebHistory(),
    routes
})

const app = createApp(App);

// Register component
// app.component('example-component', ExampleComponent);

app.use(pinia);
app.use(router);
app.mount('#app');