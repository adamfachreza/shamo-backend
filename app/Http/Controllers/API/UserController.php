<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(),'Data profile user berhasil diambil');
    }

    public function login(Request $request){
        try {
            $request->validate([
                'email' => 'email|required',
                'password'=>'required']);


                $credentials = $request(['email','password']);
                if(!Auth::attempt($credentials)){
                    return ResponseFormatter::error(['message'=>'Unauthorized'],'Authentication Failed',500);
                }


                $user = User::where('email', $request->email)->first();
                if(!Hash::check($request->password, $user->password, [])){
                    throw new \Exception('invalid Credentials');
                }

                $tokenResult = $user->createToken('authToken')->plainTextToken;
                return ResponseFormatter::success([
                    'access_token' => $tokenResult,
                    'token_type' => 'Bearer',
                    'user' => $user],'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error'=> $error,],
                'Authentication Failed', 500);
        }
    }


    public function register(Request $request)
    {
        // Validate input data
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users|max:255|unique:users,email',
            'username' => 'required|string|max:255|unique:users,id',
            'password' => 'required|string|min:6|',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'meta' => [
                    'code' => 422,
                    'status' => 'error',
                    'message' => 'Validation Failed'
                ],
                'data' => [
                    'message' => 'Invalid input data',
                    'errors' => $validator->errors()
                ]
            ], 422);
        }

        // Create user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'username' => $request->username,
            'password' => Hash::make($request->password),
        ]);

        // Generate API token
        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'success',
                'message' => 'User registered successfully'
            ],
            'data' => [
                'user' => $user,
                'access_token' => $token,
                'token_type' => 'Bearer',
            ]
        ], 200);
    }

    public function logout(Request $request)
    {
    $token = $request->user()->currentAccessToken()->delete();

    return ResponseFormatter::success($token, 'Token Revoked');
}

public function updateProfile(Request $request)
{
    $data = $request->all();

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user,'Profile Updated');
}
}
