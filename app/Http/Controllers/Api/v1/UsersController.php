<?php
namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Models\User;

class UsersController extends Controller{

    public function index(){

    }

    public function store(){
        $user = User::create([
            
        ]);
    }

    public function update(){
        
    }

    public function delete(){
        
    }
}
?>