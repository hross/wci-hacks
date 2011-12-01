using System;
using System.Collections;
using com.plumtree.openfoundation.util;
using com.plumtree.openkernel.config;
using com.plumtree.openkernel.factory;
using com.plumtree.portaluiinfrastructure.resultwrapper;
using com.plumtree.portaluiinfrastructure.statichelpers;
using com.plumtree.server;
using com.plumtree.xpshared.config;

namespace PortalUtility
{
	/// <summary>
	/// Summary description for DecryptLockboxes.
	/// </summary>
	public class DecryptLockboxes
	{
		private DecryptLockboxes() {}

		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		public static void Main(string[] args) {
			IPTSession session = CreateSession("Guest", "");

			// get the lockbox property ids
			GetLockBoxProperites(session);

			// get all encrypted values for admin
			EncryptedProperties(session, 1);

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

		/// <summary>
		/// Using any session, pass a user ID to decrypt all encrypted properties for this user.
		/// </summary>
		/// <param name="session">Session to use for decryptioin.</param>
		/// <param name="userId">User ID to decrypt properties for.</param>
		/// <returns></returns>
		public static SortedList EncryptedProperties(IPTSession session, int userId) {
			SortedList list = new SortedList();

			IPTProfileManager manager = (IPTProfileManager) session.OpenGlobalObject(PT_GLOBALOBJECTS.PT_GLOBAL_PROFILE_MANAGER, false);
			IPTUserInfo info = manager.GetUserInfo(userId);

			// find properties that are encrypted
			IPTObjectProperties userProps = manager.GetUserProperties(userId, false);
			IPTQueryResult result = userProps.GetPropertyData(PT_PROPIDS.PT_PROPID_ALL);

			for (int i = 0; i < result.RowCount(); i++) {
				// you could take out the if statement below and you'd get *all* properties for the user
				//Console.WriteLine(result.ItemAsInt(i, PT_PROPIDS.PT_PROPID_OWNERID));
				if (result.ItemAsInt(i, PT_PROPIDS.PT_PROPID_PROP_VALUETYPE) == PT_PROPERTY_TYPES.PT_PROPTYPE_ENCRYPTED) {
					//Console.WriteLine(result.ItemAsString(i, PT_PROPIDS.PT_PROPID_NAME) + " - " + result.ItemAsString(i, PT_PROPIDS.PT_PROPID_PROP_VALUE) );
					string settingName = result.ItemAsString(i, PT_PROPIDS.PT_PROPID_NAME);
					string settingUUID = result.ItemAsString(i, PT_PROPIDS.PT_PROPID_MIGRATION_UUID);
					Console.WriteLine(settingName + " = " + info.GetSetting(settingUUID));
				}
			}

			return list;
		}


		/// <summary>
		/// This function loops through the portal and finds all properties which are lock boxes
		/// (either user names or passwords). It prints out their IDs -- it could probably used with the above to
		/// grab actual info from the properties.
		/// </summary>
		/// <param name="session">The user session to use for finding the properties.</param>
		public static void GetLockBoxProperites(IPTSession session) {
			IPTObjectManager profilePageObjMgr = session.GetProfilePages();
			IPTObjectManager profileSectionObjMgr = session.GetProfileSections();

			PTObjectManagerQueryWrapper omqw = new PTObjectManagerQueryWrapper(profilePageObjMgr);
			Object[][] queryFilter = PlumtreeHelpers.GetQueryFilter(PT_PROPIDS.PT_PROPID_OBJECTID, PT_FILTEROPS.PT_FILTEROP_EQ, PT_INTRINSICS.PT_PROFILE_PAGE_CREDENTIAL_VAULT);
			omqw.Query(PT_PROPIDS.PT_PROPID_OBJECTID, -1, null, queryFilter);

			if (omqw.GetCount() > 0) {
				IPTProfilePage page = (IPTProfilePage) profilePageObjMgr.Open(1, false);
				
				object[] lockboxes = page.GetChildSections();

				for (int i = 0; i < lockboxes.Length; i++) {

					int lockBoxId = (int) lockboxes[i];
					IPTProfileSection profileSection = (IPTProfileSection) profileSectionObjMgr.Open(lockBoxId, false);
					Object[] arPropIDs = profileSection.GetChildProperties();
					if (arPropIDs.Length >= 2) {
						Console.WriteLine(XPConvert.ToInteger(arPropIDs[0]));
						Console.WriteLine(XPConvert.ToInteger(arPropIDs[1]));
					}
				}
			}
		}

		/// <summary>
		/// List properties in the portal
		/// </summary>
		/// <param name="session">Session to use for propety listing.</param>
		/// <returns></returns>
		public static SortedList ListProperties(IPTSession session) {
			SortedList list = new SortedList();

				//get all the properties for this user
				IPTProfileManager pm = (IPTProfileManager) session.OpenGlobalObject(PT_GLOBALOBJECTS.PT_GLOBAL_PROFILE_MANAGER, false);
				bool bRequestEdit = true;
				IPTObjectProperties profileEOD = pm.GetUserProperties(session.GetSessionInfo().GetCurrentUserID(), bRequestEdit);

				//put all the properties in a hashtable, indexed by object id
				XPHashtable profileData = new XPHashtable();

				XPArrayList valList;
				int propertyIndex;

				// First get non-reference property data
				IASQueryResult profileQR = GetObjectPropData(profileEOD);

				propertyIndex = 0;

				while (propertyIndex < profileQR.GetCount()) {
					// get value type
					valList = GetAllValues(profileQR, propertyIndex);
					profileData.RemoveElement(profileQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_OBJECTID));
					profileData.PutElement(profileQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_OBJECTID), valList);
					
					list.Add(profileQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_OBJECTID), profileQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_PROP_VALUETYPE));
			
					if (valList.GetSize() == 0) {
						break;
					}

					propertyIndex += valList.GetSize();
				}

				IASQueryResult profileRefQR = GetObjectPropRefData(profileEOD);
				propertyIndex = 0;

				while (propertyIndex < profileRefQR.GetCount()) {
					// get value type
					valList = GetAllValues(profileRefQR, propertyIndex);
					profileData.RemoveElement(profileRefQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_OBJECTID));
					profileData.PutElement(profileRefQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_OBJECTID), valList);
					
					list.Add(profileRefQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_OBJECTID), profileRefQR.GetFields(propertyIndex, PT_PROPIDS.PT_PROPID_PROP_VALUETYPE));

					if (valList.GetSize() == 0) {
						break;
					}

					propertyIndex += valList.GetSize();
				}
			// profile data
			return list;
		}

		/// <summary>
		/// Get a bunch of values from a query as an arraylist (utility function).
		/// </summary>
		/// <param name="qrData"></param>
		/// <param name="_nRowIndex"></param>
		/// <returns></returns>
		private static XPArrayList GetAllValues(IASQueryResult qrData, int _nRowIndex) {
			XPArrayList valList = new XPArrayList();

			int currPropID = XPConvert.ToInteger(qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_OBJECTID));
			int nextPropID;
			int valType;
			Object propVal;

			// first add the current property
			valType = XPConvert.ToInteger(qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUETYPE));
			propVal     = GetPropValue(qrData, _nRowIndex, valType);
			valList.Add(propVal);

			// now check for multiple values
			while (_nRowIndex < (qrData.GetCount() - 1)) {
				nextPropID = XPConvert.ToInteger(qrData.GetFields(_nRowIndex + 1, PT_PROPIDS.PT_PROPID_OBJECTID));

				if (nextPropID == currPropID) {
					_nRowIndex++;
					valType     = XPConvert.ToInteger(qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUETYPE));
					propVal     = GetPropValue(qrData, _nRowIndex, valType);

					if (propVal != null) {
						valList.Add(propVal);
					}
				}
				else {
					return valList;
				}
			}

			return valList;
		}

		private static Object GetPropValue(IASQueryResult qrData, int _nRowIndex, int valType) {
			Object value;

			if (qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUE) == null) {
				value = null;
			}
			else {
				switch (valType) {
					case PT_PROPERTY_TYPES.PT_PROPTYPE_DOUBLE:
						value = qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUE);

						break;

					case PT_PROPERTY_TYPES.PT_PROPTYPE_DATE:
						value = qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUE);

						break;

					case PT_PROPERTY_TYPES.PT_PROPTYPE_LONG:
						value = qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUE);

						break;

					case PT_PROPERTY_TYPES.PT_PROPTYPE_REF:
						value = qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUE);

						break;

					default:
						value = qrData.GetFields(_nRowIndex, PT_PROPIDS.PT_PROPID_PROP_VALUE);

						break;
				}
			}

			return value;
		}

		protected static IASQueryResult GetObjectPropRefData(IPTObjectProperties _ptObjProp) {
			IASQueryResult asqrObjectPropRefData = null;

			try {
				if (null != _ptObjProp) {
					IPTQueryResult qrObjectPropRefData = _ptObjProp.GetPropertyRefData(PT_PROPIDS.PT_PROPID_ALL);
					asqrObjectPropRefData = new ASQueryResultWrapper(qrObjectPropRefData);
				}
			}
			catch (Exception) {
			}

			return asqrObjectPropRefData;
		}

		protected static IASQueryResult GetObjectPropData(IPTObjectProperties _ptObjProp) {
			IASQueryResult asqrObjectPropData = null;

			try {
				if (null != _ptObjProp) {
					IPTQueryResult qrObjectPropData = _ptObjProp.GetPropertyData(PT_PROPIDS.PT_PROPID_ALL);
					asqrObjectPropData = new ASQueryResultWrapper(qrObjectPropData);
				}
			}
			catch (Exception) {
			}

			return asqrObjectPropData;
		}

		/// <summary>
		/// This used to do some stuff with lockboxes but I abandoned it. I forget what it does now.
		/// </summary>
		/// <returns></returns>
		public static string GetLockBoxInfo() {
//			// Look up lockboxes.
//			m_alProfilePages = new XPArrayList();
//			IPTObjectManager profilePageObjMgr = ((IPTSession)m_asOwner.GetUserSession()).GetProfilePages();
//			PTObjectManagerQueryWrapper omqw = new PTObjectManagerQueryWrapper(profilePageObjMgr);
//			Object[][] queryFilter = PlumtreeHelpers.GetQueryFilter(PT_PROPIDS.PT_PROPID_OBJECTID, PT_FILTEROPS.PT_FILTEROP_EQ, new Integer(PT_INTRINSICS.PT_PROFILE_PAGE_CREDENTIAL_VAULT));
//			omqw.Query(PT_PROPIDS.PT_PROPID_OBJECTID, -1, null, queryFilter);
//
//			if (omqw.GetCount() > 0) {
//				IPTProfilePage page = (IPTProfilePage)profilePageObjMgr.Open(1, false);
//				m_alProfilePages.Add(page);
//				m_numProfilePages++;
//			}
//
//			// Load username
//			IPTQueryResult ptQR = propMgr.QuerySingleObject(m_nUsernamePropID);
//			if (ptQR.RowCount() > 0) {
//				m_objUsernameProp = (IPTProperty)propMgr.Open(m_nUsernamePropID, false);
			//IPTProperty p;
			//p.GetObjectProperties()
//				ptQR = userProps.GetSinglePropertyData(m_nUsernamePropID, PT_PROPIDS.PT_PROPID_PROP_VALUE);
//				if (ptQR.RowCount() > 0) {
//					m_strUsernameValue = ptQR.ItemAsString(0, PT_PROPIDS.PT_PROPID_PROP_VALUE);			
//				}
//			}
//
//			// Load password
//			ptQR = propMgr.QuerySingleObject(m_nPasswordPropID);
//			if (ptQR.RowCount() > 0) {
//				m_objPasswordProp = (IPTProperty)propMgr.Open(m_nPasswordPropID, false);			
//				ptQR = userProps.GetSinglePropertyData(m_nPasswordPropID, PT_PROPIDS.PT_PROPID_PROP_VALUE);
//				if (ptQR.RowCount() > 0) {
//					m_strPasswordValue = ptQR.ItemAsString(0, PT_PROPIDS.PT_PROPID_PROP_VALUE);			
//				}
//			}
			return "";
		}
	}
}
