<?php

namespace App\Http\Controllers\Api\v1;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use App\Http\Resources\UserResource;
use Laravel\Sanctum\PersonalAccessToken;

class UserController extends Controller
{
    //
     public function store(StoreUserRequest $request){
        $user = [
            'Username' => $request->username,
            'PasswordHash' => Hash::make($request->password),
            'Role' => $request->Role
        ];

        User::create($user);
        return response()->json(['message' => 'User saved successfully','user' => $user], 201);
    }

    public function show($token){
        $accessToken = PersonalAccessToken::findToken($token);
        
        if ($accessToken) {
            $user = $accessToken->tokenable; // retrieves related User
            return new UserResource($user);
            }
    }
    
    public function update(UpdateUserRequest $user){

    }
}
