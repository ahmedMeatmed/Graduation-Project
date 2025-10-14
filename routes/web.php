<?php


use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\LoginController;


// Route::post('login', [LoginController::class, 'login'])->name('login.store');

Route::middleware('auth')->group(function () {

    
});

Route::get('/login', [LoginController::class, 'login'])->name('login');

Route::get('/logout', [LoginController::class, 'logout'])->name('logout');

Route::get('/{any}', fn() => view('app'))->where('any', '.*');