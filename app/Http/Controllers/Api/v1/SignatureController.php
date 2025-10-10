<?php
namespace App\Http\Controllers\Api\v1;

use App\Models\Signature;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreSignatureRequest;
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
        $signature = Signature::paginate(5);

        return response()->json($signature);
    }


    public function create(){
        return view("signature");
        }

 public function store(StoreSignatureRequest $request)
{
    // dd($request);
    $data = $request->validated();  // get validated input
    $signature = Signature::create($data); // create record
    return response()->json([
        'message' => 'Signature created successfully',
        'data' => $signature
    ], 201);
}

       
    public function update(){}
    public function edit(){}

    public function show($signature){

        $sign = Signature::findOrFail($signature); 
        return response()->json($sign);

    }

    public function delete($signature){

        $sign = Signature::find($signature);

        $sign->delete();
        
        return response()->noContent();
    }
 
}
?>