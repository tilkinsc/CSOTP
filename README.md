# CSOTP

This module is part of a chain of OTP libraries all written in different languages. See https://github.com/OTPLibraries

A simple One Time Password (OTP) library in C# (C-Sharp)

Compatible with Authy and Google Authenticator. Full support for QR code url is provided.


## Libraries Needed

No external libraries are required to use any version of CSOTP.

Targeted at .NET 4.6.2, however the only problems you might have with older versions are the OTPURI `System.Uri.EscapeDataString(String data)` function, as there used to be a `System.Web.HttpUtility.UrlEncode()` or `System.Web.HttpServerUtility.UrlEncode()` function in place of it.


## Configuration

Add the whole CSOTP.cs file into your project, or modify it to your namespace liking, or include as an external build source. Leave out the Program.cs file, as this is a test file.



_____________

## License

This library is licensed under GNU General Public License v3.0.


## Usage

To use this library, pick either TOTP or HOTP then use the provided files - giving the functions what they need. The only thing you really need to pay attention is settings. Check out the test file, as it will tell you what the default requirements is for Google Authenticator, but you should always be using Authy (it is the most lenient).


## TODO

* Optimize the whole thing. The code was translated and is still very messy. Could probably use some improvements in the hacked areas and lack of understanding of C#.
* Add comments - there are NO comments, should match up to COTP's style
