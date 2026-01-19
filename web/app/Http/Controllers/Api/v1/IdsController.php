<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class IdsController extends Controller
{
    //
   public function index()
{
    $path = 'D:\\graduation project\\IDS_Core\\IDSApp\\bin\\Release\\net8.0\\win-x64\\IDSApp.exe';
    $command = "start /B \"\" \"$path\" > \"$path\\ids.log\" 2>&1";
    exec($command);

    return response()->json(['message' => 'IDS started']);
}

public function destroy()
{
    $command = "taskkill /F /IM IDSApp.exe";
    exec($command);

    return response()->json(['message' => 'IDS stopped']);

}
}