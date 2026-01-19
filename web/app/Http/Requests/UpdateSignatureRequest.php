<?php

namespace App\Http\Requests;

use App\Models\Signature;
use Illuminate\Foundation\Http\FormRequest;

class UpdateSignatureRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        // return true;
        return $this->user()->can('update',Signature::class);
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            // Validation rules
            "engine" => "bail|required",
            "attackName" => "bail|required",
            "ruleText" => "bail|required",
            "protocol" => "bail|required",
            "protocol" => "bail|required",
            "srcPort" => "bail|required",
            "direction" => "bail|required",
            "destIp" => "bail|required",
            "destPort" => "bail|required",
            "flow" => "bail|required",
            "http" => "bail|required",
            "tls" => "bail|required",
            "contentPattern" => "bail|required",
            "sid" => "bail|required",
            "rev" => "bail|required",

        ];
    }
}
