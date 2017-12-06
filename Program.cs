/*
 * Created by SharpDevelop.
 * User: CBUD
 * Date: 12/6/2017
 * Time: 12:48 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Security.Cryptography;
using System.Text;

using CSOTP;

namespace MainProg
{
	class Program
	{
		
		public static byte[] SHA1_Encrypt(byte[] byte_secret, byte[] byte_string)
		{
			return new HMACSHA1(byte_secret).ComputeHash(byte_string);
		}
		
		public static byte[] SHA256_Encrypt(byte[] byte_secret, byte[] byte_string)
		{
			return new HMACSHA256(byte_secret).ComputeHash(byte_string);
		}
		
		public static byte[] SHA512_Encrypt(byte[] byte_secret, byte[] byte_string)
		{
			return new HMACSHA512(byte_secret).ComputeHash(byte_string);
		}
		
		
		public static void Main(string[] args)
		{
			
			// ////////////////////////////////////////////////////////////
			//   Initialization Stuff                                    //
			// ////////////////////////////////////////////////////////////
			
			const int INTERVAL	= 30;
			const int DIGITS	= 6;
			
			byte[] BASE32_SECRET = Encoding.ASCII.GetBytes("JBSWY3DPEHPK3PXP");
			byte[] SHA1_DIGEST = Encoding.ASCII.GetBytes("SHA1");
			
			const int SHA1_BITS = 160;
			
			TOTP tdata = new TOTP(BASE32_SECRET, SHA1_BITS, SHA1_Encrypt, SHA1_DIGEST, DIGITS, INTERVAL);
			HOTP hdata = new HOTP(BASE32_SECRET, SHA1_BITS, SHA1_Encrypt, SHA1_DIGEST, DIGITS);
			
			Console.WriteLine("\\\\ totp tdata \\\\");
			Console.WriteLine("tdata.digits: `" + tdata.digits + "`");
			Console.WriteLine("tdata.interval: `" + tdata.interval + "`");
			Console.WriteLine("tdata.bits: `" + tdata.bits + "`");
			Console.WriteLine("tdata.type: `" + tdata.method + "`");
			Console.WriteLine("tdata.algo: `" + tdata.algo + "`");
			Console.WriteLine("tdata.digest: `" + tdata.digest + "`");
			Console.WriteLine("tdata.base32_secret: `" + tdata.base32_secret + "`");
			Console.WriteLine("// totp tdata //\n");
			
			Console.WriteLine("\\\\ hotp hdata \\\\");
			Console.WriteLine("hdata.digits: `" + hdata.digits + "`");
			Console.WriteLine("hdata.bits: `" + hdata.bits + "`");
			Console.WriteLine("hdata.type: `" + hdata.method + "`");
			Console.WriteLine("hdata.algo: `" + hdata.algo + "`");
			Console.WriteLine("hdata.getDigest: `" + hdata.digest + "`");
			Console.WriteLine("hdata.base32_secret: `" +  hdata.base32_secret + "`");
			Console.WriteLine("// hotp hdata //\n");
			
			Console.WriteLine("Current Time: `" + (DateTimeOffset.Now.ToUnixTimeSeconds()) + "`");
			
			
			// /////////////////////////////////////////////////////////////
			//   URI Example                                              //
			// /////////////////////////////////////////////////////////////
			
			
			
			
			// /////////////////////////////////////////////////////////////
			//   BASE32 Stuff                                             //
			// /////////////////////////////////////////////////////////////
			
			// Already seeded the random generator and popped the first result
			
			const int BASE32_LEN = 16;
			
			byte[] base32_new_secret = null;
			try {
				base32_new_secret = tdata.random_base32(BASE32_LEN, OTP.DEFAULT_BASE32_CHARS);
				Console.WriteLine("Generated BASE32 Secret: `" + (Encoding.ASCII.GetString(base32_new_secret)) + "`");
			} catch(BASE32FormatError e) {
				Console.WriteLine(e);
				Environment.Exit(1);
			}
			
			Console.WriteLine(""); // line break for readability
			
			
			// /////////////////////////////////////////////////////////////
			//   TOTP Stuff                                               //
			// /////////////////////////////////////////////////////////////
			
			// Get TOTP for a time block
			//   1. Generate and load totp key into buffer
			//   2. Check for error
			
			try {
				// totp.now
				int totp_err_1 = tdata.now();
				Console.WriteLine("TOTP Generated: `" + totp_err_1 + "`");
				
				// totp.at
				int totp_err_2 = tdata.at(1, 0);
				Console.WriteLine("TOTP Generated: `" + totp_err_2 + "`");
				
				
				// Do a verification for a hardcoded code
				// Won't succeed, this code is for a timeblock far into the past
				bool tv1 = tdata.verify(576203, DateTimeOffset.Now.ToUnixTimeSeconds(), 4);
				
				// Will Succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
				bool tv2 = tdata.verify(282760, 0, 4);
				Console.WriteLine("TOTP Verification 1: `" + tv1 + "`");
				Console.WriteLine("TOTP Verification 2: `" + tv2 + "`");
			} catch(Exception e) { // HMACGenerationError || BASE32FormatError
				Console.WriteLine(e);
				Console.WriteLine("TOTP Error 2");
				Environment.Exit(1);
			}
			
			Console.WriteLine(""); // line break for readability
			
			
			// /////////////////////////////////////////////////////////////
			// HOTP Stuff                                                 //
			// /////////////////////////////////////////////////////////////
			
			// Get HOTP for token 1
			//   1. Generate and load hotp key into buffer
			//   2. Check for error
			
			try {
				int hotp_err_1 = hdata.at(1);
				Console.WriteLine("HOTP Generated at 1: `" + hotp_err_1 + "`");
				
				// Do a verification for a hardcoded code
				// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
				bool hv = hdata.verify(996554, 1);
				Console.WriteLine("HOTP Verification 1: `" + hv + "`");
			} catch(Exception e) { // HMACGenerationError || BASE32FormatError
				Console.WriteLine(e);
				Console.WriteLine("HOTP Error 1");
				Environment.Exit(1);
			}
			
			Console.ReadLine();
		}
	}
}