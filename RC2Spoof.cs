using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// This class was ripped from the plumtree XPCrypto RC2 implementation.
/// </summary>
public class RC2Spoof {
    // Fields
    private static string BASE64DIGITS;
    private MD5CryptoServiceProvider digester;
    private static bool isDebugging;
    private Random m_random;
    private const int MAX_ENCRYPTEDBIN_SIZE = 0x101;
    private const int MAX_ENCRYPTEDTEXT_SIZE = 0x202;
    private const int MAX_KEYTEXT_SIZE = 0xff;
    private static int MAX_PASSWORD_LEN;
    private const int MIN_ENCRYPTEDTEXT_SIZE = 4;
    public const char RC2_ENCRYPTION_MARKER_40 = 'P';
    private static string SECRET_DIGITS;

    // Methods
	static RC2Spoof() {
		MAX_PASSWORD_LEN = 128;
		BASE64DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		SECRET_DIGITS = "9s#.jx{';9)aQRB@6xo`a9gu43kgJZsJKGW929GAIJ@!49fci]b]1`jg4=FLK43A2(z}pWcHR#jk19sius84KD=_vz@&kd#@(jFjsKcks-158gjk3|sheh983HgH38Se";
		isDebugging = false;
	}

	public RC2Spoof() {
		this.m_random = null;
		this.m_random = new Random();
		this.digester = new MD5CryptoServiceProvider();
	}

	private int AsciiText2Bin(byte[] pucBinText, string pcAsciiText, int uiNumBytes) {
		int startIndex = 0;
		int num3 = 0;
		for (int i = 0; i < uiNumBytes; i += 2) {
			int num4 = int.Parse(pcAsciiText.Substring(startIndex, 2), NumberStyles.HexNumber);
			pucBinText[num3++] = (byte) num4;
			startIndex += 2;
		}
		return (uiNumBytes / 2);
	}

	private int ByteToInt(byte b) {
		if (b >= 0) {
			return b;
		}
		return (b + 0x100);
	}

	private int CalcHashKey(byte[] cpucKey) {
		int num = 0;
		for (int i = 0; i < cpucKey.Length; i++) {
			num = ((((num << 5) & 0xff) + (num & 0xff)) + this.ByteToInt(cpucKey[i])) & 0xff;
		}
		return num;
	}
 
	public bool CanDecrypt(string toDecrypt) {
		if ((toDecrypt == null) || (toDecrypt.Length == 0)) {
			return false;
		}
		char ch = toDecrypt[0];
		if ((ch != 'P') && (((ch < '0') || (ch > '9')) && ((ch < 'A') || (ch > 'F')))) {
			return false;
		}
		return true;
	}

 
	private int DecipherData(byte[] pcPlaintext, string pcCiphertext, string pcKeyText, int uiSizeBufOut) {
		int num2;
		if (((pcPlaintext == null) || (pcCiphertext == null)) || (((pcCiphertext.Length < 4) || (pcKeyText == null)) || (pcKeyText.Length > 0xff))) {
			return -1;
		}
		if (uiSizeBufOut < this.DecipheredTextSize(pcCiphertext)) {
			return -1;
		}
		byte[] pucBinText = new byte[0x203];
		int uiSizeBufIn = this.AsciiText2Bin(pucBinText, pcCiphertext, pcCiphertext.Length);
		try {
			num2 = this.DecipherData(pcPlaintext, pucBinText, Encoding.UTF8.GetBytes(pcKeyText), uiSizeBufIn, uiSizeBufOut);
		}
		catch (Exception) {
			return -1;
		}
		return num2;
	}

	private int DecipherData(byte[] pucPlaintext, byte[] cpucCiphertext, byte[] cpucKeyText, int uiSizeBufIn, int uiSizeBufOut) {
		int index;
		if (((pucPlaintext == null) || (cpucCiphertext == null)) || ((cpucKeyText == null) || (uiSizeBufIn > 0x101))) {
			return -1; // null string exception
		}
		for (index = 0; index < uiSizeBufOut; index++) {
			pucPlaintext[index] = 0;
		}
		int num2 = cpucCiphertext[1];
		if (num2 > uiSizeBufOut) {
			return -1; // buffer size is too small
		}
		char ch = (char) this.CalcHashKey(cpucKeyText);
		char ch2 = (char) cpucCiphertext[0];
		int siShiftBy = (ch + ch2) % 8;
		if (siShiftBy >= 8) {
			return -1; /// bad rotated bit
		}
		for (index = 0; index < num2; index++) {
			pucPlaintext[index] = (byte) this.RotByteR(cpucCiphertext[index + 2], siShiftBy);
		}
		return num2;
	}

	private int DecipheredTextSize(string strText) {
		int num = strText.Length + 1;
		if (5 > num) {
			return -1; // problem with length
		}
		if (5 <= num) {
			return (((num - 5) / 2) + 1);
		}
		return 1;
	}

	public string Decrypt(string strToDecrypt, string strKey) {
		if (!this.CanDecrypt(strToDecrypt)) {
			return ""; // The encrypted string is invalid, it does not start with a valid marker character
		}
		if (Convert.ToChar(strToDecrypt[0]) == 'P') {
			byte[] buf = System.Convert.FromBase64String(strToDecrypt.Substring(3));
			byte[] destinationArray = null;
			string sKey = null;
				RC2 rc = new RC2();
				sKey = strToDecrypt.Substring(1, 2) + strKey;
				byte[] abBytesOut = this.GetCryptKey(sKey);
				if (isDebugging) {
					Console.Out.WriteLine("==== The Secret Key ======");
					PrintOutBytesArray(abBytesOut);
					Console.Out.WriteLine("==== The End Of The Secret Key ======");
				}
				rc.setKey(abBytesOut);
				byte[] sourceArray = rc.decrypt(buf);
				destinationArray = new byte[sourceArray.Length - 1];
				Array.Copy(sourceArray, 0, destinationArray, 0, sourceArray.Length - 1);
				return Encoding.UTF8.GetString(destinationArray, 0, destinationArray.Length);
		}
		int uiSizeBufOut = this.DecipheredTextSize(strToDecrypt);
		byte[] pcPlaintext = new byte[uiSizeBufOut];
		int num2 = this.DecipherData(pcPlaintext, strToDecrypt, strKey, uiSizeBufOut);
		if (num2 == 0) {
			return "";
		}
		byte[] bytes = new byte[num2];
		for (int i = 0; i < num2; i++) {
			bytes[i] = pcPlaintext[i];
		}
		return Encoding.UTF8.GetString(bytes);
	}

	public string Encrypt(string strToEncrypt, string strKey) {
		byte[] btToEncode = null;
		string sKey = null;
		byte[] sourceArray = null;
		sourceArray = Encoding.UTF8.GetBytes(strToEncrypt);

		int length = sourceArray.Length;
		byte[] destinationArray = new byte[length + 1];
		Array.Copy(sourceArray, 0, destinationArray, 0, length);
		destinationArray[length] = 0;

			RC2 rc = new RC2();
			sKey = ("" + BASE64DIGITS[Math.Abs((this.m_random.Next() % BASE64DIGITS.Length))]) + (BASE64DIGITS[Math.Abs((this.m_random.Next() % BASE64DIGITS.Length))]) + strKey;
			byte[] keyBytes = this.GetCryptKey(sKey);
			rc.setKey(keyBytes);
			btToEncode = rc.encrypt(destinationArray);

		return (("" + 'P') + sKey.Substring(0, 2) + System.Convert.ToBase64String(btToEncode));
	}

	private byte[] GetCryptKey(string sKey) {
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
		if (isDebugging) {
			Console.WriteLine("My key: " + Encoding.UTF8.GetString(destinationArray, 0, destinationArray.Length));
			PrintOutBytesArray(destinationArray);
		}
		byte[] buffer3 = new byte[0x10];

		byte[] buffer4 = this.digester.ComputeHash(destinationArray);
		for (int j = 0; j < 5; j++) {
			buffer3[j] = buffer4[j];
		}
		for (int k = 5; k < 0x10; k++) {
			buffer3[k] = 0;
		}

		return buffer3;
	}

	private static void PrintOutBytesArray(byte[] abBytesOut) {
		for (int i = 0; i < abBytesOut.Length; i++) {
			Console.Out.WriteLine(string.Concat(new object[] { "\tByteArray[", i, "] = ", abBytesOut[i], "  [", Convert.ToChar(abBytesOut[i]), "]" }));
		}
	}

	private int RotByteR(byte ccByte, int siShiftBy) {
		int num2 = ccByte & 0xff;
		while (siShiftBy > 0) {
			int num = (num2 & 1) & 0xff;
			num2 = (num2 >> 1) & 0xff;
			if (num > 0) {
				num2 = (num2 | 0x80) & 0xff;
			}
			siShiftBy--;
		}
		return num2;
	}

    // Nested Types
    private class RC2
    {
        // Fields
        private int[] Cbuf;
        private int[] Key;
        private int KeyStrength;
        private byte[] P;

        // Methods
		public RC2() {
			this.KeyStrength = 40;
			this.Key = new int[0x40];
			this.Cbuf = new int[4];
			this.P = new byte[] { 
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
		}

		public byte[] arrayXor(byte[] array1, byte[] array2) {
			if (array1.Length != array2.Length) {
				return null;
			}
			byte[] buffer = new byte[array1.Length];
			for (int i = 0; i < array1.Length; i++) {
				buffer[i] = (byte) ((array1[i] ^ array2[i]) & 0xff);
			}
			return buffer;
		}

 
		public byte[] decrypt(byte[] buf) {
			byte[] buffer = new byte[8];
			for (int i = 0; i < (buf.Length / 8); i++) {
				byte[] destinationArray = new byte[8];
				Array.Copy(buf, i * 8, destinationArray, 0, 8);
				byte[] buffer3 = this.decryptBlock(destinationArray);
				Array.Copy(this.arrayXor(buffer3, buffer), 0, buf, i * 8, 8);
				buffer = destinationArray;
			}
			int length = buf.Length;
			int num3 = buf[length - 1];
			if (isDebugging) {
				Console.Out.WriteLine("========================================");
				PrintOutBytesArray(buf);
				Console.Out.WriteLine("========================================");
			}
			byte[] buffer4 = new byte[length - num3];
			Array.Copy(buf, 0, buffer4, 0, length - num3);
			return buffer4;
		}

 
		public byte[] decryptBlock(byte[] buf) {
			for (int i = 0; i < 4; i++) {
				this.Cbuf[i] = ((buf[(i * 2) + 1] << 8) | (buf[i * 2] & 0xff)) & 0xffff;
			}
			int j = 0x3f;
			for (int k = 0; k < 5; k++) {
				j = this.r_mix(j);
			}
			this.r_mash();
			for (int m = 0; m < 6; m++) {
				j = this.r_mix(j);
			}
			this.r_mash();
			for (int n = 0; n < 5; n++) {
				j = this.r_mix(j);
			}
			byte[] buffer = new byte[8];
			for (int index = 0; index < 4; index++) {
				buffer[index * 2] = (byte) this.Cbuf[index];
				buffer[(index * 2) + 1] = (byte) (this.Cbuf[index] >> 8);
			}
			return buffer;
		}

 
		public byte[] encrypt(byte[] buf) {
			int length = buf.Length;
			int num2 = 8 - (length % 8);
			byte[] destinationArray = new byte[length + num2];
			Array.Copy(buf, 0, destinationArray, 0, length);
			for (int i = 0; i < num2; i++) {
				destinationArray[length + i] = (byte) num2;
			}
			byte[] buffer2 = new byte[8];
			for (int j = 0; j < (destinationArray.Length / 8); j++) {
				byte[] buffer3 = new byte[8];
				Array.Copy(destinationArray, j * 8, buffer3, 0, 8);
				byte[] buffer4 = this.arrayXor(buffer3, buffer2);
				buffer2 = this.encryptBlock(buffer4);
				Array.Copy(buffer2, 0, destinationArray, j * 8, 8);
			}
			return destinationArray;
		}

 

 
		public byte[] encryptBlock(byte[] buf) {
			for (int i = 0; i < 4; i++) {
				this.Cbuf[i] = ((buf[(i * 2) + 1] << 8) | (buf[i * 2] & 0xff)) & 0xffff;
			}
			int j = 0;
			for (int k = 0; k < 5; k++) {
				j = this.mix(j);
			}
			this.mash();
			for (int m = 0; m < 6; m++) {
				j = this.mix(j);
			}
			this.mash();
			for (int n = 0; n < 5; n++) {
				j = this.mix(j);
			}
			byte[] buffer = new byte[8];
			for (int index = 0; index < 4; index++) {
				buffer[index * 2] = (byte) this.Cbuf[index];
				buffer[(index * 2) + 1] = (byte) (this.Cbuf[index] >> 8);
			}
			return buffer;
		}

 

 
		private void mash() {
			this.Cbuf[0] += this.Key[this.Cbuf[3] & 0x3f];
			this.Cbuf[1] += this.Key[this.Cbuf[0] & 0x3f];
			this.Cbuf[2] += this.Key[this.Cbuf[1] & 0x3f];
			this.Cbuf[3] += this.Key[this.Cbuf[2] & 0x3f];
		}

 

 
		private int mix(int j) {
			this.Cbuf[0] = (((this.Cbuf[0] + this.Key[j]) + (this.Cbuf[3] & this.Cbuf[2])) + (~this.Cbuf[3] & this.Cbuf[1])) & 0xffff;
			this.Cbuf[0] = this.rol(this.Cbuf[0], 1);
			j++;
			this.Cbuf[1] = (((this.Cbuf[1] + this.Key[j]) + (this.Cbuf[0] & this.Cbuf[3])) + (~this.Cbuf[0] & this.Cbuf[2])) & 0xffff;
			this.Cbuf[1] = this.rol(this.Cbuf[1], 2);
			j++;
			this.Cbuf[2] = (((this.Cbuf[2] + this.Key[j]) + (this.Cbuf[1] & this.Cbuf[0])) + (~this.Cbuf[1] & this.Cbuf[3])) & 0xffff;
			this.Cbuf[2] = this.rol(this.Cbuf[2], 3);
			j++;
			this.Cbuf[3] = (((this.Cbuf[3] + this.Key[j]) + (this.Cbuf[2] & this.Cbuf[1])) + (~this.Cbuf[2] & this.Cbuf[0])) & 0xffff;
			this.Cbuf[3] = this.rol(this.Cbuf[3], 5);
			j++;
			return j;
		}

 

 
		private void r_mash() {
			this.Cbuf[3] -= this.Key[this.Cbuf[2] & 0x3f];
			this.Cbuf[2] -= this.Key[this.Cbuf[1] & 0x3f];
			this.Cbuf[1] -= this.Key[this.Cbuf[0] & 0x3f];
			this.Cbuf[0] -= this.Key[this.Cbuf[3] & 0x3f];
		}

 

 
		private int r_mix(int j) {
			this.Cbuf[3] = this.ror(this.Cbuf[3], 5);
			this.Cbuf[3] = (((this.Cbuf[3] - this.Key[j]) - (this.Cbuf[2] & this.Cbuf[1])) - (~this.Cbuf[2] & this.Cbuf[0])) & 0xffff;
			j--;
			this.Cbuf[2] = this.ror(this.Cbuf[2], 3);
			this.Cbuf[2] = (((this.Cbuf[2] - this.Key[j]) - (this.Cbuf[1] & this.Cbuf[0])) - (~this.Cbuf[1] & this.Cbuf[3])) & 0xffff;
			j--;
			this.Cbuf[1] = this.ror(this.Cbuf[1], 2);
			this.Cbuf[1] = (((this.Cbuf[1] - this.Key[j]) - (this.Cbuf[0] & this.Cbuf[3])) - (~this.Cbuf[0] & this.Cbuf[2])) & 0xffff;
			j--;
			this.Cbuf[0] = this.ror(this.Cbuf[0], 1);
			this.Cbuf[0] = (((this.Cbuf[0] - this.Key[j]) - (this.Cbuf[3] & this.Cbuf[2])) - (~this.Cbuf[3] & this.Cbuf[1])) & 0xffff;
			j--;
			return j;
		}

 

 
		private int rol(int s, int numBits) {
			long num = (s << numBits) | ((long) ((ulong) (s >> (0x10 - numBits))));
			return (int) num;
		}

		private int ror(int s, int numBits) {
			s &= 0xffff;
			long num = ((long) ((ulong) (s >> numBits))) | ((s << (0x10 - numBits)) & 0xffff);
			return (int) num;
		}

		public void setKey(byte[] keyBytes) {
			int num = (this.KeyStrength + 7) / 8;
			int num2 = 0xff % ((int) Math.Pow(2, (double) ((8 + this.KeyStrength) - (8 * num))));
			byte[] destinationArray = new byte[0x80];
			Array.Copy(keyBytes, 0, destinationArray, 0, keyBytes.Length);
			int length = keyBytes.Length;
			for (int i = length; i <= 0x7f; i++) {
				destinationArray[i] = this.P[(destinationArray[i - 1] + destinationArray[i - length]) % 0x100];
			}
			destinationArray[0x80 - num] = this.P[destinationArray[0x80 - num] & num2];
			for (int j = 0x7f - num; j >= 0; j--) {
				destinationArray[j] = this.P[destinationArray[j + 1] ^ destinationArray[j + num]];
			}
			for (int k = 0; k < this.Key.Length; k++) {
				this.Key[k] = ((destinationArray[(k * 2) + 1] & 0xff) << 8) | ((destinationArray[k * 2] & 0xff) & 0xffff);
			}
		}
    }
}
