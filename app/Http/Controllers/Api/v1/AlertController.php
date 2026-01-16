<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateAlertRequest;
use App\Http\Resources\AlertResource;
use App\Models\Alert;

class AlertController extends Controller
{
    //
    public function index(){
        $alerts = Alert::all();
        
        return AlertResource::collection($alerts);;
    }

    public function show($alert){

        $alert = Alert::findOrFail($alert);

        return new AlertResource($alert);
    }

    public function update(UpdateAlertRequest $request,$alert){
        $alert = Alert::findOrFail($alert);
        $alert->update(["Status"=>$request->status , "AssignedTo"=>$request->assignedTo]);

        return new AlertResource($alert);
    }
}
