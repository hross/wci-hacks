using System;
using com.plumtree.openkernel.config;
using com.plumtree.openkernel.factory;
using com.plumtree.server;
using com.plumtree.xpshared.config;

namespace Bea.BidServices {
	/// <summary>
	/// Summary description for SessionManager.
	/// </summary>
	public sealed class SessionManager {
		private SessionManager() {}

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
