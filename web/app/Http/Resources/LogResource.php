<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class LogResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'LogID' => $this->LogID,
            'SourceIP' => $this->SourceIP,
            'DestinationIP' => $this->DestinationIP,
            'PacketSize' => $this->PacketSize,
            'IsMalicious' => $this->IsMalicious,
            'Protocol' => $this->Protocol,
            'SrcPort' => $this->SrcPort,
            'DestPort' => $this->DestPort,
            'PayloadSize' => $this->PayloadSize,
            'TcpFlags' => $this->TcpFlags,
            'FlowDirection' => $this->FlowDirection,
            'PacketCount' => $this->PacketCount,
            'Duration' => $this->Duration,
            'MatchedSignatureId' => $this->MatchedSignatureId,
            'Timestamp' => $this->Timestamp,
                ];
    }
}
