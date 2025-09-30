import axios from "axios";
import { defineStore } from "pinia";
import { ref } from "vue";


export const useDataStore = defineStore('data',()=>{

    let logs=ref([]);
    const FetchLogs = async () =>{
        await axios.get('http://127.0.0.1:8000/api/v1/logs')
        .then((response)=>{
            logs.value = response.data;
        })
        .catch((response)=>{
            return response;
        })
    }
    return{
        FetchLogs,
        logs,
    };
})