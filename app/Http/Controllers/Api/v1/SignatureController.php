<?php
namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Models\Signature;

class SignatureController extends Controller{

    public function index(){
        $signature = Signature::paginate(10);

        return response()->json($signature);
    }


    public function store(){
        
    }

       
    public function update(){
        
    }

    public function show($signature){
        $sign = Signature::findOrFail($signature);

        return response()->json($sign);
    }

    public function delete($signature){

        $sign = Signature::find($signature);

        $sign->delete();
        
        return response()->noContent();
    }
}
?>