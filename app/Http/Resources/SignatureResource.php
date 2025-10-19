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
            'SignId' => $this -> SignId,
            'Engine' => $this -> Engine,
            'AttackName' => $this -> AttackName,
            'RuleText' => $this -> RuleText,
            'Protocol' => $this -> Protocol,
            'SrcIp' => $this -> SrcIp,
            'SrcPort' => $this -> SrcPort,
            'Direction' => $this -> Direction,
            'DestIp' => $this -> DestIp,
            'DestPort' => $this -> DestPort,
            'Flow' => $this -> Flow,
            'Http' => $this -> Http,
            'Tls' => $this -> Tls,
            'ContentPattern' => $this -> ContentPattern,
            'Sid' => $this -> Sid,
            'Rev' => $this -> Rev,
            'CreatedAt' => $this -> CreatedAt,
        ];
    }
}
