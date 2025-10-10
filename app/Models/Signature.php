<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Signature extends Model
{
    //
    protected $table = "Signatures";
    protected $primaryKey = "signId";
    
    public $timestamps = false;

    protected $fillable = [
            "engine",
            "attackName",
            "ruleText" ,
            "protocol" ,
            "protocol",
            "srcPort" ,
            "direction",
            "destIp",
            "destPort",
            "flow",
            "http",
            "tls",
            "contentPattern",
            "sid",
            "rev",
            "created_at"
    ];

}
