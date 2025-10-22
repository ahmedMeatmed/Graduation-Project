import './bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import { createApp } from 'vue';
import { createWebHistory, createRouter  } from "vue-router";
import { createPinia } from 'pinia';
import routes from './router/routes';
import App from './components/App.vue'




const pinia = createPinia();
const router = createRouter({
    
    history:createWebHistory(),
    routes
})

router.beforeEach((to, from, next) => {
  const isAuthenticated = !!localStorage.getItem('token') ;

  if (to.meta.requiresAuth && !isAuthenticated) {
    next('/login') // redirect if not authenticated
  } else if (to.path === '/login' && isAuthenticated) {
    next('/dashboard') // prevent logged-in users from going back to login
  } else {
    next() // allow
  }
})

const app = createApp(App);


app.use(pinia);
app.use(router);
app.mount('#app');