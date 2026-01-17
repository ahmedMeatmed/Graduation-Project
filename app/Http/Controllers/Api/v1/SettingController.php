<?php

namespace App\Http\Controllers\Api\v1;

use App\Models\Setting;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Resources\SettingResource;
use App\Http\Requests\StoreSettingRequest;
use App\Http\Requests\UpdateSettingRequest;

class SettingController extends Controller
{
    //

    public function index()
    {
        $settings = Setting::all();
            

        return SettingResource::collection($settings);
    }

    public function show($id)
    {
        $setting = Setting::findOrFail($id);
        return new SettingResource($setting);
    }

    public function update(UpdateSettingRequest $request, $id)
    {
        $setting = Setting::findOrFail($id);
        $filename = time() . '.' . $request->file('file')->extension();

        $path = $request->file('file')->storeAs(
            'uploads',
            $filename
        );

       $setting->update(['SettingValue' => $request->SettingValue]);
        return new SettingResource($setting);
    }


}
