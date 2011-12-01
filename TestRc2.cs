using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Bea.BidServices;
using com.plumtree.openfoundation.security;
using com.plumtree.server;
using com.plumtree.uiinfrastructure.application.varpacks;
using com.plumtree.uiinfrastructure.web;

namespace CatalogTestHarness
{
	/// <summary>
	/// Summary description for TestRc2.
	/// </summary>
	public class TestRc2
	{

		private const string SECRET_DIGITS = "9s#.jx{';9)aQRB@6xo`a9gu43kgJZsJKGW929GAIJ@!49fci]b]1`jg4=FLK43A2(z}pWcHR#jk19sius84KD=_vz@&kd#@(jFjsKcks-158gjk3|sheh983HgH38Se";
		private const int MAX_PASSWORD_LEN = 128;

		private static byte[] iv = new byte[] { 
		0xd9, 120, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 40, 0xe9, 0xfd, 0x79, 0x4a, 160, 0xd8, 0x9d, 
		0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 100, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 
		0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 9, 0x81, 0x7d, 50, 
		0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 11, 240, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 130, 
		0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 20, 0xa7, 140, 0xf1, 220, 
		0x12, 0x75, 0xca, 0x1f, 0x3b, 190, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 60, 0xb6, 0x26, 
		0x6f, 0xbf, 14, 0xda, 70, 0x69, 7, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 3, 
		0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 6, 0xc3, 0xd5, 0x2f, 200, 0x66, 30, 0xd7, 
		8, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 170, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a, 
		150, 0x1a, 210, 0x71, 90, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 4, 0x18, 0xa4, 0xec, 
		0xc2, 0xe0, 0x41, 110, 15, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 80, 0xa1, 0xf4, 0x70, 0x39, 
		0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 180, 0x7a, 0xfc, 2, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31, 
		0x2d, 0x5d, 250, 0x98, 0xe3, 0x8a, 0x92, 0xae, 5, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9, 
		0xd3, 0, 230, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 1, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 
		13, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 12, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e, 
		0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 10, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
	};

		public TestRc2()
		{
			//
			// TODO: Add constructor logic here
			//
		}

		public static void MainX() {

			IPTSession session = SessionManager.CreateSession("Administrator", "");

			IPTSession guestSession = session.ImpersonateUser("Guest");

			IPTSessionInfo info = guestSession.GetSessionInfo();

			object [][] val = info.LookupPreference("myTestPref", 0);

			Console.WriteLine("Preference value is: " + val[1][0].ToString());

			IApplication application = ApplicationManager.GetInstance().GetApplication(AppConstants.MAIN_APPLICATION_NAME.ToString());
			
			application.GetCachingManager().SetEntry("", val[1][0].ToString());
			
			return;


			IXPCrypto xpcpPass = XPCrypto.GetInstance(XPCryptoType.RC2_40);
			string pwd = xpcpPass.Encrypt("password", "pthack");

			// Create a new instance of the RC2CryptoServiceProvider class
			// and automatically generate a Key and IV.
			RC2CryptoServiceProvider rc2CSP = new RC2CryptoServiceProvider();

			Console.WriteLine("Effective key size is {0} bits.", rc2CSP.EffectiveKeySize);
	
			string strToDecrypt = "P4uUnYhwaRmldZEyAee3QWuoA==";//"6200E0C962077DDBACEBCC3BEA5C3BEA260B45CCC695A003"; 
			string strKey = "blahuser"; //"Administrator";

			// Get the key and IV.

			if (strToDecrypt.StartsWith("P")) {
				strKey = strToDecrypt.Substring(1, 2) + strKey;
			} else {

			}
			string sKey = strToDecrypt.Substring(1, 2) + strKey;
			
			byte[] key =  GetCryptKey(sKey);//rc2CSP.Key;
			byte[] IV = iv; // rc2CSP.IV;

			string encryptedText = strToDecrypt.Substring(3);
			byte[] encrypted = System.Convert.FromBase64String(encryptedText);

			//Get a decryptor that uses the same key and IV as the encryptor.
			ICryptoTransform decryptor = rc2CSP.CreateDecryptor(key, IV);

			// Now decrypt the previously encrypted message using the decryptor
			// obtained in the above step.
			MemoryStream msDecrypt = new MemoryStream(encrypted);
			CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);

			// Read the decrypted bytes from the decrypting stream
			// and place them in a StringBuilder class.

			StringBuilder roundtrip = new StringBuilder();
            
			int b = 0;

			do {
				b = csDecrypt.ReadByte();
                
				if (b != -1) {
					roundtrip.Append((char)b);
				}

			} while (b != -1);
 

			// Display the original data and the decrypted data.
			//Console.WriteLine("Original:   {0}", original);
			Console.WriteLine("Round Trip: {0}", roundtrip);

			Console.ReadLine();
		}

		
		private static byte[] GetCryptKey(string sKey) {
			if (sKey.Length > MAX_PASSWORD_LEN) {
				return null; // key length exceeds maximum
			}
			byte[] sourceArray = Encoding.UTF8.GetBytes(sKey);
			int num = 0;
			for (int i = 0; i < sourceArray.Length; i++) {
				num ^= sourceArray[i];
			}
			if (num < 0) {
				num = 0;
			}
			byte[] destinationArray = new byte[sourceArray.Length + 1];
			Array.Copy(sourceArray, 0, destinationArray, 0, sourceArray.Length);
			destinationArray[sourceArray.Length] = (byte) SECRET_DIGITS[num % SECRET_DIGITS.Length];

			byte[] buffer3 = new byte[0x10];

			MD5CryptoServiceProvider digester = new MD5CryptoServiceProvider();
			byte[] buffer4 = digester.ComputeHash(destinationArray);
			for (int j = 0; j < 5; j++) {
				buffer3[j] = buffer4[j];
			}
			for (int k = 5; k < 0x10; k++) {
				buffer3[k] = 0;
			}

			return buffer3;
		}

		private static void DoEncryption(byte[] key, byte[] iv) {
		
			RC2CryptoServiceProvider rc2CSP = new RC2CryptoServiceProvider();

			// Get an encryptor.
			ICryptoTransform encryptor = rc2CSP.CreateEncryptor(key, iv);

			// Encrypt the data as an array of encrypted bytes in memory.
			MemoryStream msEncrypt = new MemoryStream();
			CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

			// Convert the data to a byte array.
			string original = "Here is some data to encrypt.";
			byte[] toEncrypt = Encoding.ASCII.GetBytes(original);

			// Write all data to the crypto stream and flush it.
			csEncrypt.Write(toEncrypt, 0, toEncrypt.Length);
			csEncrypt.FlushFinalBlock();

			// Get the encrypted array of bytes.
			byte[] encrypted = msEncrypt.ToArray();

			///////////////////////////////////////////////////////
			// This is where the data could be transmitted or saved.          
			///////////////////////////////////////////////////////
		}
	}
}
