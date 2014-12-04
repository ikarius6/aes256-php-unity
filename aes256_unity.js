/*
	AES256 v1.1 MrJack
*/

import System;
import System.IO;
import System.Text;
import System.Security.Cryptography;
import SimpleJSON;
private var KEY:String = "MY_SUPER_DUPER_SECRET"; 

public function encrypt(clearText:String) {
	return EncryptRJ256(KEY, clearText);
}

public function decrypt(encryptText:String) {
	return DecryptRJ256(KEY, encryptText);
}

public function EncryptRJ256(pkey:String, clearText:String) {
	var myRijndael:RijndaelManaged = new RijndaelManaged();
	myRijndael.Padding = PaddingMode.Zeros;
	myRijndael.Mode = CipherMode.CBC;
	myRijndael.KeySize = 256;
	myRijndael.BlockSize = 256;
	myRijndael.GenerateIV();
	
	var key:byte[] = System.Text.Encoding.UTF8.GetBytes(pkey);
	
	var encryptor:ICryptoTransform = myRijndael.CreateEncryptor(key, myRijndael.IV);
	var ms:MemoryStream = new MemoryStream();
	var cs:CryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
	
	var encryptByte:byte[] = System.Text.Encoding.UTF8.GetBytes(clearText);
	
	cs.Write (encryptByte, 0, encryptByte.Length);
	cs.FlushFinalBlock();
	
	var encrypted:byte[] = ms.ToArray ();
	
	return Convert.ToBase64String (myRijndael.IV+encrypted);
}

public function DecryptRJ256(pkey:String, encryptedText:String) {
	var myRijndael:RijndaelManaged = new RijndaelManaged();
	myRijndael.Padding = PaddingMode.Zeros;
	myRijndael.Mode = CipherMode.CBC;
	myRijndael.KeySize = 256;
	myRijndael.BlockSize = 256;
	myRijndael.GenerateIV();
	
	var key:byte[] = System.Text.Encoding.UTF8.GetBytes(pkey);
	
	var decryptor:ICryptoTransform = myRijndael.CreateDecryptor(key, myRijndael.IV);
	var encryptByte:byte[] = Convert.FromBase64String(encryptedText);
	var encrypted:byte[] = new byte[encryptByte.Length];
	
	var ms:MemoryStream = new MemoryStream(encryptByte);
	var cs:CryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
	cs.Read(encrypted, 0, encrypted.Length);
			
	var encr:byte[] = new byte[encryptByte.Length-32];
	var iic = 0;
	for(iic=32;iic<encrypted.length;iic++)
		encr[iic-32] = encrypted[iic];
	Debug.Log( System.Text.Encoding.UTF8.GetString(encr) );
	
	//return System.Text.Encoding.UTF8.GetString(encrypted);
	return System.Text.Encoding.UTF8.GetString(encr);
}