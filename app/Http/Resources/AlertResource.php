<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class AlertResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'AlertID'=> $this->AlertID,
            'LogID'=> $this->LogID,
            'Message'=> $this->Message,
            'AttackType'=> $this->AttackType,
            'Severity'=> $this->Severity,
            'SourceIP'=> $this->SourceIP,
            'DestinationIP'=> $this->DestinationIP,
            'Timestamp'=> $this->Timestamp,
            'Status'=> $this->Status,
            'AssignedTo'=> $this->AssignedTo,
        ];
    }
}
