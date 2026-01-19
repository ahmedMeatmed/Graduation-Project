<?php

namespace App\Http\Requests;

use App\Models\Signature;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class StoreSignatureRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('create',Signature::class);
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
       
        return[
        'engine'        => 'required|string|in:snort,suricata', // only allow supported engines
        'attackName'    => 'required|string|max:255',
        'ruleText'      => 'required|string',
        'protocol'      => 'required|string|in:tcp,udp,icmp,ip,http,tls,any',
        'srcIp'         => 'required|string|max:50',
        'srcPort'       => 'required|string|max:50',
        'direction'     => 'required|string|in:->,<-,<>',
        'destIp'        => 'required|string|max:50',
        'destPort'      => 'required|string|max:50',
        
        // optional fields
        'flow'          => 'nullable|string|max:255',
        'http'          => 'nullable|string|max:255',
        'tls'           => 'nullable|string|max:255',
        'contentPattern'=> 'nullable|string|max:255',

        // signature metadata
        'sid'           => 'required|integer',
        'rev'           => 'required|integer|min:1',
        'created_at'    => 'nullable|date',
        ];
    }
}
