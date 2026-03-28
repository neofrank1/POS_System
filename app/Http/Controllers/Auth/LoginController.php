<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('auth')->only('logout');
    }
    
    protected function credentials(Request $request)
    {
        // Add status = 1 to the credentials array to ensure the user is active
        return array_merge($request->only($this->username(), 'password'), ['status' => 1]);
    }
    

    protected function validateLogin(Request $request)
    {
        $request->validate([
            $this->username() => 'required|string',
            'password' => 'required|string',
        ]);

        $user = User::where($this->username(), $request->input($this->username()))->first();

        if ($user && !$user->status) {
            throw ValidationException::withMessages([
            $this->username() => [trans('User is inactive (Needs to be activated by admin)')],
            ]);
        }
    }

    protected function attemptLogin(Request $request)
    {
        $credentials = $this->credentials($request);

        $user = User::where($this->username(), $credentials[$this->username()])->first();

        if ($user && $user->status == 1) {
            // User exists and is active, so proceed with the normal login check
            return $this->guard()->attempt(
                $credentials, $request->boolean('remember')
            );
        } elseif ($user && $user->status == 0) {
            // User exists but is inactive, fail the login and return a message
            return back()->withErrors([
            $this->username() => 'Your account is inactive. Please contact support.'
            ]);
        } else {
            // User does not exist, so we will send the error using the credentials
            return back()->withErrors([
            $this->username() => trans('auth.failed')
            ]);
        }
    }
}
