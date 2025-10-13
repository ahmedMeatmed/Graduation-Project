<?php

// use App\Http\Controllers\TestController;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


use App\Http\Controllers\Api\v1\AlertController;
use App\Http\Controllers\Api\v1\LogConroller;
use App\Http\Controllers\Api\v1\SignatureController;
use App\Http\Controllers\Api\v1\UserController;
use App\Http\Controllers\LoginController;

Route::group(['prefix' => "v1"],function(){

    Route::apiResource('signatures',SignatureController::class);

    Route::get('signatures/search/{attack}', [SignatureController::class, 'search']);

    Route::apiResource('logs',LogConroller::class);

    Route::apiResource('users',UserController::class);

    Route::apiResource('alerts',AlertController::class);

    Route::post('/logout', [LoginController::class, 'logout']);

})->middleware('auth:sanctum');


