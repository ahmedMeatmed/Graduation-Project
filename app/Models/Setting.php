<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Setting extends Model
{
    //
    protected $fillable = [
        'SettingValue',
    ];
    
    protected $primaryKey = "SettingID";
    protected $table = "Settings";
     public $timestamps = false;

}
