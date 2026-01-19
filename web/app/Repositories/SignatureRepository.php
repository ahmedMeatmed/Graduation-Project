<?php
namespace App\Repositories;

use App\Models\Signature;

class SignatureRepository{

    public function searchByAttackName(string $attack){
        
        return Signature::where('AttackName','like',"%$attack%")->get();
    }

}