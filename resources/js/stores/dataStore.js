import axios from "axios";
import { defineStore } from "pinia";
import { ref } from "vue";


export const useDataStore = defineStore('data',()=>{

    let logs = ref([]);
    let singleLog = ref([]);

    let alerts = ref([]);
    let singleAlert = ref([]);

    let signatures = ref([]);
    let singleSignature = ref([]);

    let firstPage = ref(null);
    let lastPage = ref(null);

    let errors = ref([]);


    const FetchLogs = async () =>{
        await axios.get('http://127.0.0.1:8000/api/v1/logs')
        .then((response)=>{
            //  console.log(response.data);
             logs.value = response.data;
            //  console.log(logs.value)
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchSingleLog = async (log)=>{
        await axios.get(`http://127.0.0.1:8000/api/v1/logs/${log}`)
        .then((response)=>{
            singleLog.value = response.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchAlerts = async ()=>{
        await axios.get("http://127.0.0.1:8000/api/v1/alerts")
        .then((response)=>{
            alerts.value = response.data
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchSingleAlert = async (alert)=>{
        await axios.get(`http://127.0.0.1:8000/api/v1/alerts/${alert}`)
        .then((response)=>{
            singleAlert.value = response.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }
     const FetchSignatures = async (page)=>{
        await axios.get(`http://127.0.0.1:8000/api/v1/signatures?page=${page}`)
        .then((response)=>{
            firstPage.value = response.data.from
            lastPage.value = response.data.last_page
            signatures.value = response.data.data
            // console.log(signatures.value);
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }

    const FetchSingleSignature =  async (signature)=>{
        await axios.get(`http://127.0.0.1:8000/api/v1/signatures/${signature}`)
        .then((response)=>{
            singleSignature.value = response.data;
        })
        .catch((response)=>{
            console.log(response.data+"can't Fetch");
        })
    }
    const searchSignature = (attack) => {
  axios.get(`http://127.0.0.1:8000/api/v1/signatures/search/${attack}`)
    .then((response) => {
    //   console.log(response.data.data);

      signatures.value = response.data;
    })
    .catch((error) => {
      console.log("can't fetch");
    });
    }

    const storeSignature =async (signature)=>{
        await axios.post("http://127.0.0.1:8000/api/v1/signatures",signature,{
            headers:{
                'Content-Type' :  'application/json'
            }
        })
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
        await axios.post()
    }



    return{
        FetchLogs,FetchSingleLog,
        FetchAlerts,FetchSingleAlert,
        FetchSignatures,searchSignature,
        FetchSingleSignature,storeSignature,
        singleSignature,
        logs,singleLog,
        alerts,singleAlert,
        signatures,firstPage,lastPage,
    };
})