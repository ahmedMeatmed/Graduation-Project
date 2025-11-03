import api from "../bootstrap";
import { defineStore } from "pinia";
import { ref } from "vue";
import { useRouter } from "vue-router";


export const useDataStore = defineStore('data',()=>{

    const router = useRouter();

    let logs = ref([]);
    let singleLog = ref([]);

    let alerts = ref([]);
    let singleAlert = ref([]);

    let signatures = ref([]);
    let singleSignature = ref([]);

    let firstPage = ref(null);
    let lastPage = ref(null);

    let errors = ref([]);
    let valid = ref(false);

    const user = ref({
        username:'',
        role : '',
    })


    const FetchLogs = async () =>{
        await api.get('logs')
        .then((response)=>{
             logs.value = response.data.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchSingleLog = async (log)=>{
        await api.get(`logs/${log}`)
        .then((response)=>{
            singleLog.value = response.data.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchAlerts = async ()=>{
        await api.get("alerts")
        .then((response)=>{
            // console.log(response);
            alerts.value = response.data.data
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchSingleAlert = async (alert)=>{
        await api.get(`alerts/${alert}`)
        .then((response)=>{
            singleAlert.value = response.data.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }
     const FetchSignatures = async (page)=>{
        await api.get(`signatures?page=${page}`)
        .then((response)=>{
            firstPage.value = response.data.meta.current_page
            lastPage.value = response.data.meta.last_page
            signatures.value = response.data.data
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchSingleSignature =  async (signature)=>{
            // console.log(signature);

        await api.get(`signatures/${signature}`)
        .then((response)=>{
            console.log(response);
            singleSignature.value = response.data.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }
    const searchSignature = (attack) => {
        console.log(attack);
        api.get(`signatures/search/${attack}`)
            .then((response) => {
            signatures.value = response.data.data;
            })
            .catch((error) => {
            console.log("can't fetch");
            });
    }

    const storeSignature =async (signature)=>{
        await api.post("signatures",signature)
        .then((response)=>{
            console.log("✅ Created:", response.data);
        })
        .catch((error)=>{
            errors.value = error.response.data.errors;
            console.error(errors.value.attackName[0]);
            // console.error(errors.value.attackName[0]);
        })
    }

    const storeUser = async ()=>{
        await api.post('users',)
        .then((response)=>{

        })
        .catch((error)=>{

        })
    }

    const FetchUsers = async()=>{
        await api.get('users')
        .then((response)=>{

        })
        .catch((error)=>{

        })

    }

    const FetchUser = async()=>{
        let token = localStorage.getItem('token');
        await api.get(`users/${token}`)
        .then((response)=>{
            user.value.username = response.data.data.userName;
            user.value.role = response.data.data.role;
        })
        .catch((error)=>{
            console.log(error);
        })
    }

    const FetchSingleUser = async(user)=>{
        await api.get(`users/${user}`)
        .then((response)=>{

        })
        .catch((error)=>{

        })
    }

    const logout = async ()=>{
        await api.post('logout')
        .then((response)=>{
            console.log("✅ Logged out:", response.data);
            localStorage.removeItem('token');
            router.push('/login');
        })
        .catch((error)=>{
            console.error("Logout failed:", error);
        });
    }
   
    const loginUser = async (credentials)=>{
        
        await axios.post('http://127.0.0.1:8000/api/login',credentials)
        .then((response)=>{
            localStorage.setItem('token', response.data.data.token);
            user.value.username = response.data.data.userName;
            user.value.role = response.data.data.role;
            router.push('/dashboard');
        })
        .catch(()=>{
            valid.value = true;
        });
    }

    return{
        FetchLogs,FetchSingleLog,
        FetchAlerts,FetchSingleAlert,
        FetchSignatures,searchSignature,
        FetchSingleSignature,storeSignature,
        logout,storeUser,FetchUsers,FetchSingleUser,
        singleSignature,loginUser,valid,user,FetchUser,
        logs,singleLog,
        alerts,singleAlert,
        signatures,firstPage,lastPage,
    };
})