<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class SignatureResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'SignId' => $this -> signId,
            'Engine' => $this -> engine,
            'AttackName' => $this -> attackName,
            'RuleText' => $this -> ruleText,
            'Protocol' => $this -> protocol,
            'SrcIp' => $this -> srcIp,
            'SrcPort' => $this -> srcPort,
            'Direction' => $this -> direction,
            'DestIp' => $this -> destIp,
            'DestPort' => $this -> destPort,
            'Flow' => $this -> flow,
            'Http' => $this -> http,
            'Tls' => $this -> tls,
            'ContentPattern' => $this -> contentPattern,
            'Sid' => $this -> sid,
            'Rev' => $this -> rev,
            'CreatedAt' => $this -> created_at,
            'Severity' => $this -> Severity,
        ];
    }
}
