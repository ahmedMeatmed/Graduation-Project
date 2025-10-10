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
// class SignatureSearchService
// {
//     public function searchByAttackName(string $keyword)
//     {
//         return Signature::where('attackName', 'like', "%{$keyword}%")->get();
//     }
// }