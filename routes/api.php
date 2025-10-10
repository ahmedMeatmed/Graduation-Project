<?php

// use App\Http\Controllers\TestController;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


use App\Http\Controllers\Api\v1\AlertController;
use App\Http\Controllers\Api\v1\LogConroller;
use App\Http\Controllers\Api\v1\SignatureController;

Route::group(['prefix' => "v1"],function(){

    Route::apiResource('signatures',SignatureController::class);

    Route::get('signatures/search/{attack}', [SignatureController::class, 'search']);

    Route::apiResource('logs',LogConroller::class);

    Route::apiResource('users',LogConroller::class);

    Route::apiResource('alerts',AlertController::class);

})->middleware('auth:sanctum');

