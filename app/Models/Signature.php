<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Signature extends Model
{
    //
    protected $table = "Signatures";
    protected $primaryKey = "SignId";
    
    public $timestamps = false;

    protected $fillable = [
        'Engine',
        'AttackName',
        'RuleText',
        'Protocol',
        'SrcIp',
        'SrcPort',
        'Direction',
        'DestIp',
        'DestPort',
        'Flow',
        'Http',
        'Tls',
        'ContentPattern',
        'Sid',
        'Rev',
        'CreatedAt'
    ];


}
