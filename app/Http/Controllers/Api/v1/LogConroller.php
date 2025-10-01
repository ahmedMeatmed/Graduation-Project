<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Models\Log;
use Illuminate\Http\Request;

class LogConroller extends Controller
{
    //
    public function index(){
        $logs = Log::all();
        
        return response()->json($logs);
    }

    public function show($log){

        $log = Log::findOrFail($log);

        return response()->json($log);
    }

    public function delete(){
        $logs = Log::all();

        $logs->delete();
        
        return response()->noContent();
    }
}
