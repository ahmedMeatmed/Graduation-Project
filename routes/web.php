<?php


use Illuminate\Support\Facades\Route;

Route::get('/', function () {return view('auth.login');})->name('login');

Route::get('/dashboard',function(){ return view('dashboard');})->where('dashboard','.*')->name('dashboard');

Route::get('signatures/create',function(){ return view("signature");});


Route::get('/{any}', function () {return view('dashboard');})->where('any', '.*');