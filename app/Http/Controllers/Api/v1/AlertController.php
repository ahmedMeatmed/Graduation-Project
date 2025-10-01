<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Models\Alert;
use Illuminate\Http\Request;

class AlertController extends Controller
{
    //
    public function index(){
        $alerts = Alert::all();

        return response()->json($alerts);
    }

    public function show($alert){

        $alert = Alert::findOrFail($alert);

        return response()->json($alert);
    }

    public function delete($alert){

        $alert = Alert::findOrFail($alert);

        $alert->delete();

        return response("alert resolved");
    }
}
