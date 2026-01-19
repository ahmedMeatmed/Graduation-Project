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
    public function index(){
        $users = User::all();
        return UserResource::collection($users);
    }
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
    
    public function update(UpdateUserRequest $request, $user){
        $data = $request->validated();  // get validated input
        $usr = User::findOrFail($user); 
        if(isset($data['PasswordHash'])){
            $data['PasswordHash'] = Hash::make($data['PasswordHash']);
        }
        $usr->update($data); // update record
        return response()->json([
            'message' => 'User updated successfully',
            'data' => $usr
        ], 200);

    }
    public function destroy($user){
        $usr = User::findOrFail($user); 
        $usr->delete(); // delete record
        return response()->json([
            'message' => 'User deleted successfully'
        ], 200);

    }
}
