<?php

// use Illuminate\Support\Facades\Auth;

use App\Http\Controllers\LoginController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {return view('auth.login');})->name('login');

Route::post('login', [LoginController::class, 'login'])->name('login.store');
// Route::post('logout', [LoginController::class, 'logout'])->name('logout');

Route::middleware('auth')->group(function () {

    Route::get('/dashboard', fn() => view('dashboard'))->name('dashboard');

    Route::get('signatures/create', fn() => view("signature"));

    Route::get('/{any}', fn() => view('dashboard'))->where('any', '.*');
});