<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Http\Resources\AlertResource;
use App\Models\Alert;
use Illuminate\Http\Request;

class AlertController extends Controller
{
    //
    public function index(){
        $alerts = Alert::all();
        
        return AlertResource::collection($alerts);;
    }

    public function show($alert){

        $al = Alert::findOrFail($alert);

        return new AlertResource($al);
    }
}
