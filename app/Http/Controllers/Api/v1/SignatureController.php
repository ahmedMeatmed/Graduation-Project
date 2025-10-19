<?php
namespace App\Http\Controllers\Api\v1;

use App\Models\Signature;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreSignatureRequest;
use App\Http\Resources\SignatureResource;
use App\Services\SignatureSearchService;

class SignatureController extends Controller{

    protected SignatureSearchService $signatureService;

    public function __construct(SignatureSearchService $signatureService)
    {
        $this->signatureService = $signatureService;
    }

    // Custom search route
    public function search($attack)
    {
        $results = $this->signatureService->searchByAttackName($attack);
        return response()->json($results);
    }

    public function index(){
        $signatures = Signature::paginate(5);

        return SignatureResource::collection($signatures);
    }


    public function store(StoreSignatureRequest $request){
        // dd($request);
        $data = $request->validated();  // get validated input
        $signature = Signature::create($data); // create record
        return response()->json([
            'message' => 'Signature created successfully',
            'data' => $signature
        ], 201);
    }

       
    public function update(){}


    public function show($signature){

        $sign = Signature::findOrFail($signature); 

        return new SignatureResource($sign);

    }
 
}
?>