<?php


use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\LoginController;




Route::get('/{any}', fn() => view('app'))->where('any', '.*');