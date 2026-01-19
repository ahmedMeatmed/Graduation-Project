<?php
namespace App\Services;

use App\Repositories\SignatureRepository;

class SignatureSearchService{
    protected $signatures;

    public function __construct(SignatureRepository $signatures)
    {
        $this->signatures = $signatures;
    }

    public function searchByAttackName($attack){
        return $this->signatures->searchByAttackName($attack);
    }
}
