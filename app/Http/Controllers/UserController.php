<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    //

    public function store(StoreUserRequest $user){}
    
    public function update(UpdateUserRequest $user){}


    public function login(LoginRequest $user){
        dd($user->all());

        $credentials = ['username' => $user->username,'password' => $user->password];

         if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
 
            return redirect()->intended('dashboard');
        }
    }

    public function logout(){}
}
