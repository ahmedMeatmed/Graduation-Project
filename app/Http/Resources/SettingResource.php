<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class SettingResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            "settingId" => $this->SettingID,
            "settingKey" => $this->SettingKey,
            "settingValue" => $this->SettingValue,
            "dataType" => $this->DataType,
            "category" => $this->Category,
            "description" => $this->Description,
            "isEditable" => $this->IsEditable,
            "lastModified" => $this->LastModified,
        ];
    }
}
