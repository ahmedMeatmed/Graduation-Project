<?php

namespace App\Http\Requests;

use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;

class StoreUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('create',User::class);
        // return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        // return [
        //     //
        //     "Username" => "bail|required|max:50",
        //     "PasswordHash" => "bail|required|password|max:15",
        //     "Role" => "bail|required|max:2",

        // ];
        return[
            'username' => 'required|string|min:3|max:50|unique:users,username',
            'password' => 'required|string|min:8',
            'Role'     => 'required|string',
        ];
    }
}
