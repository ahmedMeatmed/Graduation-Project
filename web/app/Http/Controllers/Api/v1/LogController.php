<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Http\Resources\LogResource;
use App\Models\Log;
use Illuminate\Http\Request;

class LogController extends Controller
{
    //
    public function index(){

        $logs = Log::all();
        return LogResource::collection($logs);
    }

    public function show($log){

        $log = Log::findOrFail($log);

        return new LogResource($log);
    }

}
