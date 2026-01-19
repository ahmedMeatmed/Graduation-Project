import Logs from "..\\components/Logs.vue";
import Log from "..\\components/Log.vue";
import Alerts from "..\\components/Alerts.vue";
import Alert from "..\\components/Alert.vue";
import Settings from "..\\components/Settings.vue";
import Profile from "..\\components/Profile.vue";
import About from "..\\components/About.vue";
import Contact from "..\\components/Contact.vue";
import Dashboard from "..\\components/Dashboard.vue";
import Signature from "../components/Signature.vue";
import Login from "../components/Login.vue";
import AuthLayout from "../components/AuthLayout.vue";



const routes =[
    { path : '/login' ,component: Login },
    {   path : '/' ,
        component:AuthLayout ,
        meta: { requiresAuth: true },
        children:[
            { path : 'dashboard' ,component: Dashboard },
            { path : 'logs' ,component: Logs },
            { path : "logs/:log" ,component: Log },
            { path : 'alerts' ,component: Alerts },
            { path : "alerts/:alert" ,component: Alert },
            { path : "signatures/:signature" ,component: Signature },
            { path : 'settings' ,component: Settings },
            { path : 'profile' ,component: Profile },
            { path : 'about' ,component: About },
            { path : 'contact' ,component: Contact },
        ]
    },
    
];

export default routes;