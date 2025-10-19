<?php

namespace App\Http\Controllers\Api\v1;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    //
     public function store(StoreUserRequest $request){

        // dd($request);
        
        $user = [
            'Username' => $request->username,
            'PasswordHash' => Hash::make($request->password),
            'Role' => $request->Role
        ];

        User::create($user);
        return response()->json(['message' => 'User saved successfully','user' => $user], 201);
        }
    
    public function update(UpdateUserRequest $user){

    }
}
