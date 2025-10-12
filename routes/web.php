<?php

// use Illuminate\Support\Facades\Auth;

use App\Http\Controllers\LoginController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {return view('auth.login');});

Route::post('login',[LoginController::class,'login'])->name('login');

Route::middleware('auth')->group(function(){

Route::get('/dashboard',function(){ return view('dashboard');})->name('dashboard');

Route::get('signatures/create',function(){ return view("signature");});

Route::get('/{any}', function () {return view('dashboard');})->where('any', '.*');

});
