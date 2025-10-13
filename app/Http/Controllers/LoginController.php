<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{

    public function login(LoginRequest $request)
{
    $credentials = [
        'Username' => $request->username,
         'password' => $request->password,
    ];

    if (Auth::attempt($credentials)) {
        // Regenerate session to prevent fixation attacks
        // dd($credentials);//here
        $request->session()->regenerate();
        return redirect()->intended(route('dashboard'));

        // return "Authinticated";
        // redirect('/dashboard');
    }

    return back()->withErrors([
        'username' => 'The provided credentials do not match our records.',
    ]);
}

   public function logout(Request $request){
    Auth::logout();
 
    $request->session()->invalidate();
 
    $request->session()->regenerateToken();
 
    return redirect('/');
}

}
