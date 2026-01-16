<?php
namespace App\Http\Controllers\Api\v1;

use App\Models\Signature;
use App\Http\Controllers\Controller;
use App\Http\Requests\SearchSignatureRequest;
use App\Http\Requests\StoreSignatureRequest;
use App\Http\Requests\UpdateSignatureRequest;
use App\Http\Resources\SignatureResource;
use App\Services\SignatureSearchService;

class SignatureController extends Controller{


    // Custom search route
    public function search(SearchSignatureRequest $request,SignatureSearchService $search)
    {
        $results = $search->searchByAttackName($request->attack);
        // dd($results);
        return response()->json($results);
    }

    public function index(){
        $signatures = Signature::paginate(5);
        return SignatureResource::collection($signatures);
    }


    public function store(StoreSignatureRequest $request){
        $data = $request->validated();  // get validated input
        $signature = Signature::create($data); // create record
        return response()->json([
            'message' => 'Signature created successfully',
            'data' => $signature
        ], 201);
    }

       
    public function update($signature, UpdateSignatureRequest $request){
        $data = $request->validated();  // get validated input
        $sign = Signature::findOrFail($signature); 
        $sign->update($data); // update record
        return response()->json([
            'message' => 'Signature updated successfully',
            'data' => $sign
        ], 200);

    }


    public function show($signature){

        $sign = Signature::findOrFail($signature); 

        return new SignatureResource($sign);

    }
    public function destroy($signature){
        $sign = Signature::findOrFail($signature); 
        $sign->delete(); // delete record
        return response()->json([
            'message' => 'Signature deleted successfully'
        ], 200);

    }
 
}
?>