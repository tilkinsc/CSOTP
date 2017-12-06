/*
 * Created by SharpDevelop.
 * User: CBUD
 * Date: 12/6/2017
 * Time: 12:49 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Text;
using System.Runtime.Serialization;

namespace CSOTP
{
	
	
	[Serializable()]
	public class HMACGenerationError : System.Exception
	{
		public HMACGenerationError() : base() { }
		public HMACGenerationError(string message) : base(message) { }
		public HMACGenerationError(string message, System.Exception inner) : base(message, inner) { }
	
		protected HMACGenerationError(SerializationInfo info, StreamingContext context) { }
	}
	
	[Serializable()]
	public class BASE32FormatError : System.Exception
	{
		public BASE32FormatError() : base() { }
		public BASE32FormatError(string message) : base(message) { }
		public BASE32FormatError(string message, System.Exception inner) : base(message, inner) { }
	
		protected BASE32FormatError(SerializationInfo info, StreamingContext context) { }
	}
	
	
	public enum OTPType {
		OTP, TOTP, HOTP
	}
	
	/// <summary>
	/// Description of Class1.
	/// </summary>
	public class OTP
	{
		public static readonly char[] DEFAULT_BASE32_CHARS = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
			'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
			'6', '7'
		};
		
		public int digits { get; set; }
		public int bits { get; set; }
		public OTPType method { get; set; }
		public Func<byte[], byte[], byte[]> algo { get; set; }
		public byte[] digest { get; set; }
		public byte[] base32_secret { get; set; }
		
		protected Random random;
		
		public OTP(byte[] base32_secret, int bits, Func<byte[], byte[], byte[]> algo, byte[] digest, int digits)
		{
			random = new Random();
			random.Next(1,2);
			this.base32_secret = base32_secret;
			this.bits = bits;
			this.algo = algo;
			this.digest = digest;
			this.digits = digits;
			this.method = OTPType.OTP;
		}
		
		public int generate(long input, byte[] output)
		{
			int secret_len = this.base32_secret.Length;
			int desired_secret_len = (secret_len / 8) * 5;
			
			if (this.bits % 8 != 0)
				throw new HMACGenerationError("generate `this.bits` must be divisble by 8 (got " + this.bits + ")");
			
			int bit_size = this.bits / 8;
			
			byte[] byte_string = this.int_to_bytestring(input);
			byte[] _byte_secret = this.byte_secret(secret_len, desired_secret_len + 1);
			byte[] hmac = this.algo(_byte_secret, byte_string);
			
			if (hmac == null)
				throw new HMACGenerationError("generate `hmac` returned null from supplied decrypt function");
			
			int offset = (hmac[bit_size - 1] & 0xF);
			int code =
				(
					(hmac[offset] & 0x7F) << 24 |
					(hmac[offset+1] & 0xFF) << 16 |
					(hmac[offset+2] & 0xFF) << 8  |
					(hmac[offset+3] & 0xFF)
				) % (int) Math.Pow(10, this.digits);
			
			if (output != null) {
				byte[] temp = Encoding.ASCII.GetBytes(code.ToString("G").PadLeft(this.digits));
				Array.Copy(temp, output, this.digits);
			}
			
			return code;
		}
		
		public byte[] byte_secret(int size, int len)
		{
			if (size % 8 != 0)
				throw new BASE32FormatError("byte_secret `size` must be divisble by 8 (got " + size + ")");
			
			byte[] out_str = new byte[len];
			
			int n = 5;
			for (int i=0; ; i++) {
				n = -1;
				out_str[i*5] = 0;
				for (int block=0; block<8; block++) {
					int offset = (3 - (5*block) % 8);
					int octet = (block*5) / 8;
					
					int c = 0;
					if (i*8+block < this.base32_secret.Length)
						c = this.base32_secret[i*8+block] & 0xFF;
					
					if (c >= 'A' && c <= 'Z')
						n = c - 'A';
					if (c >= '2' && c <= '7')
						n = 26 + c - '2';
					if (n < 0) {
						n = octet;
						break;
					}
					
					out_str[i*5+octet] |= BitConverter.GetBytes(-offset > 0 ? n >> -offset : n << offset)[0];
					if (offset < 0)
						out_str[i*5+octet+1] = BitConverter.GetBytes(-(8 + offset) > 0 ? n >> -(8 + offset) : n << (8 + offset))[0];
				}
				if (n < 5)
					break;
			}
			
			return out_str;
		}
		
		public byte[] int_to_bytestring(long integer)
		{
			return new byte[] {
				0, 0, 0, 0,
				BitConverter.GetBytes(integer >> 24)[0],
				BitConverter.GetBytes(integer >> 16)[0],
				BitConverter.GetBytes(integer >> 8 )[0],
				BitConverter.GetBytes(integer)[0]
			};
		}
		
		public byte[] random_base32(int len, char[] chars) {
			len = len > 0 ? len : 16;
			if (len % 8 != 0)
				throw new BASE32FormatError("random_base32 `len` must be divisble by 8 (got " + len + ")");
			
			byte[] bytes = new byte[len];
			for (int i=0; i<len; i++)
				bytes[i] = (byte)chars[random.Next() % 32];
			return bytes;
		}
	}
	
	public class TOTP : OTP
	{
		public int interval { get; set; }
		
		public TOTP(byte[] base32_secret, int bits, Func<byte[], byte[], byte[]> algo, byte[] digest, int digits, int interval)
			: base(base32_secret, bits, algo, digest, digits)
		{
			this.interval = interval;
			this.method = OTPType.TOTP;
		}
		
		public bool compare(int key, int increment, long for_time)
		{
			return this.compare(
				Encoding.ASCII.GetBytes(key.ToString("G").PadLeft(base.digits)),
				increment,
				for_time);
		}
		
		public bool compare(byte[] key, int increment, long for_time)
		{
			byte[] time_str = new byte[base.digits];
			this.at(for_time, increment, time_str);
			
			for (int i=0; i<key.Length; i++)
				if (i > time_str.Length || key[i] != time_str[i])
					return false;
			return true;
		}
		
		public int at(long for_time, int counter_offset)
		{
			return this.at(for_time, counter_offset, null);
		}
		
		public int at(long for_time, int counter_offset, byte[] output)
		{
			return base.generate(this.timecode(for_time) + (long)counter_offset, output);
		}
		
		public int now()
		{
			return this.now(null);
		}
		
		public int now(byte[] output)
		{
			return base.generate(this.timecode(DateTimeOffset.Now.ToUnixTimeSeconds()), output);
		}
		
		public bool verify(int key, long for_time, int valid_window)
		{
			return this.verify(
				Encoding.ASCII.GetBytes(key.ToString("G").PadLeft(base.digits, '0')),
				for_time,
				valid_window);
		}
		
		public bool verify(byte[] key, long for_time, int valid_window)
		{
			if (valid_window < 0)
				return false;
			if (valid_window > 0) {
				for (int i=-valid_window; i<valid_window; i++)
					if (this.compare(key, i, for_time) == true)
						return true;
			}
			return this.compare(key, 0, for_time);
		}
		
		public long valid_until(long for_time, int valid_window)
		{
			return for_time + (this.interval * valid_window);
		}
		
		public long timecode(long for_time)
		{
			if (for_time <= 0)
				return 0;
			return (long)((double)for_time/(double)this.interval);
		}
	}
	
	public class HOTP : OTP
	{
		public HOTP(byte[] base32_secret, int bits, Func<byte[], byte[], byte[]> algo, byte[] digest, int digits)
			: base(base32_secret, bits, algo, digest, digits)
		{
			this.method = OTPType.HOTP;
		}
		
		public bool compare(int key, int counter)
		{
			return this.compare(
				Encoding.ASCII.GetBytes(key.ToString("G").PadLeft(base.digits, '0')),
				counter);
		}
		
		public bool compare(byte[] key, int counter)
		{
			byte[] cnt_str = new byte[base.digits];
			this.at(counter, cnt_str);
			
			for (int i=0; i<key.Length; i++)
				if (i > cnt_str.Length || key[i] != cnt_str[i])
					return false;
			return true;
		}
		
		public int at(int counter)
		{
			return this.at(counter, null);
		}
		
		public int at(int counter, byte[] output)
		{
			return base.generate(counter, output);
		}
		
		public bool verify(int key, int counter)
		{
			return this.verify(
				Encoding.ASCII.GetBytes(key.ToString("G").PadLeft(base.digits, '0')),
				counter);
		}
		
		public bool verify(byte[] key, int counter)
		{
			return this.compare(key, counter);
		}
	}
}
