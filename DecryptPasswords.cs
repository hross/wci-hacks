using System;
using System.Security.Cryptography;
using System.Text;
using com.plumtree.openfoundation.security;
using com.plumtree.openfoundation.util;
using com.plumtree.openkernel.config;

namespace CatalogTestHarness
{
	/// <summary>
	/// Summary description for DecryptPasswords.
	/// </summary>
	public class DecryptPasswords {
		// AES encryption root key for portal configuration
		// this never changes
		private static byte[] Aes128Key = new byte[] {126, 1, 67, 91, 99, 10, 117, 112, 58, 107, 6, 81, 93, 52, 20, 59 };

		public static void LoadSettings(IOKComponent component) {
			string dbhost = "";
			string dbuser = "";
			string dbpwd = "";
			string dbport = "";
			string dbtype = "";

			IOKSetting[] aSettings = component.querySettings();
			for(int i = 0; i < aSettings.Length; i++) {
				IOKSetting setting = aSettings[i];
				String sSettingName = setting.getName();
				sSettingName = sSettingName.Substring(sSettingName.IndexOf(":") + 1).ToLower();

				if(sSettingName.Equals("dbhost")) {
					dbhost = setting.getStringValue();
				} else if(sSettingName.Equals("username")) {
					dbuser = setting.getStringValue();
				} else if(sSettingName.Equals("encrypted-password")) {
					dbpwd = setting.getStringValue();
				} else if(sSettingName.Equals("port")) {
					dbport = setting.getStringValue();
				} else if(sSettingName.Equals("dbtype")) {
					dbtype = setting.getStringValue();
				}

				dbpwd = Decrypt(dbpwd, Aes128Key);
			}
		}

		private const int SaltSize = 16;
		private const int MaxKeyBytes = SaltSize;
	
		public static string Decrypt(string cipherText, byte[] key) {

			if (cipherText[0] != 'S') { return null; } // check cipher for AES indication

			// create the salt array
			byte[] salt = new byte[SaltSize];

			// get the decoded base64 array of cipher text
			byte[] sourceArray = System.Convert.FromBase64String(cipherText.Substring(1, cipherText.Length-1));
			if (sourceArray.Length <= SaltSize) { return null; } // it at least must have a salt value

			// get the salt value from the start of the cipher text
			Array.Copy(sourceArray, 0, salt, 0, SaltSize);

			// get the actual cipher text
			byte[] cipherTextBytes = new byte[sourceArray.Length - SaltSize];
			Array.Copy(sourceArray, SaltSize, cipherTextBytes, 0, cipherTextBytes.Length);

			// check the key
			if (key == null) { return null; }
			if (key.Length != MaxKeyBytes) { return null; }

			// use AES/Rijndael to decrypt
			RijndaelManaged managed = new RijndaelManaged();
			managed.KeySize = MaxKeyBytes * 8;
			managed.BlockSize = 0x80;
			managed.Mode = CipherMode.CBC;
			managed.Padding = PaddingMode.PKCS7;
			managed.Key = key;
			managed.IV = salt;
			byte[] bytes = managed.CreateDecryptor().TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);

			// return UTF-8 encoded result
			return new string(Encoding.UTF8.GetChars(bytes));
		}

	
		public static string PortalDecrypt(string cipherText, byte[] key) {
			XPAESCrypto crypto = new XPAESCrypto(XPCryptoType.AES_128);
			return crypto.Decrypt(cipherText, Aes128Key);
		}
	}
}
