<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateAlertRequest;
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

    public function update(UpdateAlertRequest $request,$alert){
        $al = Alert::findOrFail($alert);
        $al->update([$al->Status => "Resolved"]);
        $al = Alert::findOrFail($alert);
        dd($request);
        return $al;

    }
}
