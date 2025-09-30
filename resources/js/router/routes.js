import Logs from "..\\components/Logs.vue";
import Log from "..\\components/Log.vue";
import Alerts from "..\\components/Alerts.vue";
import Alert from "..\\components/Alert.vue";
import Settings from "..\\components/Settings.vue";
import Profile from "..\\components/Profile.vue";
import About from "..\\components/About.vue";
import Contact from "..\\components/Contact.vue";
import Dashboard from "..\\components/Dashboard.vue";



const routes =[
    { path : '/dashboard' ,component: Dashboard },
    { path : '/logs' ,component: Logs },
    { path : "/log/:log" ,component: Log },
    { path : '/alerts' ,component: Alerts },
    { path : "/alerts/:alert" ,component: Alert },
    { path : '/settings' ,component: Settings },
    { path : '/profile' ,component: Profile },
    { path : '/about' ,component: About },
    { path : '/contact' ,component: Contact },

];

export default routes;