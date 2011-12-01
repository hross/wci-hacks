using System;
using com.plumtree.openfoundation.security;
using com.plumtree.openfoundation.util;
using com.plumtree.openkernel.config;
using com.plumtree.openkernel.factory;
using com.plumtree.portalpages.admin.editors.webservice;
using com.plumtree.portaluiinfrastructure.classtypedescriptors.providerframework;
using com.plumtree.server;
using com.plumtree.xpshared.config;

namespace Bea.BidServices {
	/// <summary>
	/// Main entry point class for the application.
	/// </summary>
	public class DecryptWebServices {
		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		public static void MainOld(string[] args) {
			CrackWebServices();
		}
		
		public static void CrackWebServices() {
			IPTSession session = CreateSession("Administrator", "");

			// get all web service info for the target portal
			IPTObjectManager serviceManager = session.GetWebServices();
			IPTQueryResult result = serviceManager.Query(PT_PROPIDS.PT_PROPID_OBJECTID, -1, new int[] {PT_PROPIDS.PT_PROPID_OBJECTID}, 0, -1, null);

			Console.Write("This will print basic auth users and passwords for web services that use them...\n");
			Console.Write("-------------------");
			Console.Write("ID\tLogin\tPassword\n\n");

			for (int i = 0; i < result.RowCount(); i++) {
				IPTWebService webService = 
					(IPTWebService) session.GetWebServices().Open(result.ItemAsInt(i, PT_PROPIDS.PT_PROPID_OBJECTID), false);
				IXPPropertyBag providerInfo = webService.GetProviderInfo();

				// get the necryped password
				IXPCrypto xpcpPass = XPCrypto.GetInstance(XPCryptoType.AES_128);
				string cryptPassword = WSModelHelper.PBReadString(providerInfo, AExtensibilityConstants.PT_PROPBAG_HTTPGADGET_BASICAUTHPASSWORD, "");

				// get the login
				string login = WSModelHelper.PBReadString(providerInfo, AExtensibilityConstants.PT_PROPBAG_HTTPGADGET_BASICAUTHNAME, "");

				// let's try to decrypt
				if ((cryptPassword.Length > 0) && (login.Length > 0)) {
					Console.Write(webService.GetObjectID() + "\t");
					Console.Write(login.Replace("\n", "") + "\t");
					string password = xpcpPass.Decrypt(cryptPassword, login);
					Console.Write(password.Replace("\n", "") + "\n");
				}
			}

			Console.Write("Press <Enter> to terminate...");
			Console.ReadLine();
		}


		/// <summary>
		/// Create an administrative session (IPTSession) given a username and password.
		/// </summary>
		/// <param name="user">The user name</param>
		/// <param name="password">The password</param>
		/// <returns></returns>
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