<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{

    public function login(LoginRequest $request)
{
    $credentials = ['Username' => $request->username,'password' => $request->password];

    if (Auth::attempt($credentials)) {

        $user = Auth::user();
        $token = $user->createToken('auth_token');    
        return ['token' => $token->plainTextToken];
    }

    return back()->withErrors([
        'username' => 'The provided credentials do not match our records.',
    ]);
}

   public function logout(){
    $user = Auth::user();
    $user->currentAccessToken()->delete();
    return response()->json([
        'message' => 'Logged out successfully',
    ]);
}

}
