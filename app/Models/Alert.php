<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Alert extends Model
{
    //
    public $timestamps = false;

    protected $fillable = [
        "Status"
    ];
    protected $table = "Alerts";
    protected $primaryKey = "AlertId";
}
