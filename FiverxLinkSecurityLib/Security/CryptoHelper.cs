using System;
using System.IO;
using FiverxLinkSecurityLib.Global;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace FiverxLinkSecurityLib.Security
{
  public class CryptoHelper
  {
    private static IBufferedCipher RSACreateCipher(bool forEncryption, AsymmetricKeyParameter keyparameter)
    {
      IBufferedCipher cipher = CipherUtilities.GetCipher(Standards.DefEncryptionRSA);
      cipher.Init(forEncryption, keyparameter);
      return cipher;
    }

    public static string RSAEncyptWithx509Cert(string pfadx509Cert, string text)
    {
      AsymmetricKeyParameter publicKey = KeyHelper.GetPublicKeyFromX509Cert(pfadx509Cert);
      return RSAEncryptWithKey(publicKey, text);
    }

    public static string RSAEncryptWithKey(AsymmetricKeyParameter publicKey, string text)
    {
      byte[] originalDataBytes = Standards.DefEncoding.GetBytes(text);
      return Convert.ToBase64String(RSAEncryptData(publicKey, originalDataBytes));
    }

    private static byte[] RSAEncryptData(AsymmetricKeyParameter publicKey, byte[] originalDataBytes)
    {

      bool isEncryption = true;

      byte[] encryptedDataArray;

      using (MemoryStream originalDataStream = new MemoryStream(originalDataBytes, false))
      {
        using (MemoryStream encryptedDataStream = new MemoryStream())
        {
          IBufferedCipher rsacipher = RSACreateCipher(isEncryption, publicKey);
          using (CipherStream cipherStream = new CipherStream(originalDataStream, rsacipher, null))
          {

            int oneByte;
            while ((oneByte = cipherStream.ReadByte()) >= 0)
            {
              encryptedDataStream.WriteByte((byte)oneByte);
            }

            cipherStream.Close();
            cipherStream.Dispose();
          }

          encryptedDataArray = encryptedDataStream.ToArray();

          encryptedDataStream.Close();
          encryptedDataStream.Dispose();
        }

        originalDataStream.Close();
        originalDataStream.Dispose();
      }
      return encryptedDataArray;
    }

    public static string RSADecryptWithPkcs12Cert(string pfadZertifikat, string encryptedData, string password)
    {
      return RSADecryptWithKey(KeyHelper.GetPrivateKeyFromPkcsStore(pfadZertifikat, password), encryptedData);
    }

    public static string RSADecryptWithKey(AsymmetricKeyParameter privateKey, string encryptedData)
    {
      byte[] encryptedDataBytes = Convert.FromBase64String(encryptedData);
      return Standards.DefEncoding.GetString(RSAEntschluesselDaten(privateKey, encryptedDataBytes));
    }

    private static byte[] RSAEntschluesselDaten(AsymmetricKeyParameter privateKey, byte[] encryptedDataBytes)
    {
      bool isEncryption = false;

      MemoryStream enryptedDataSream = new MemoryStream(encryptedDataBytes, false);
      MemoryStream decryptedDataStream = new MemoryStream();
      IBufferedCipher aesCipher = RSACreateCipher(isEncryption, privateKey);
      CipherStream decodedCipherStream = new CipherStream(enryptedDataSream, aesCipher, null);

      int oneByte;
      while ((oneByte = decodedCipherStream.ReadByte()) >= 0)
      {
        decryptedDataStream.WriteByte((byte)oneByte);
      }

      decodedCipherStream.Close();
      decryptedDataStream.Close();

      return decryptedDataStream.ToArray();
    }

    private static IBufferedCipher AESCreateCipher(bool forEncryption, byte[] aesKey, byte[] iv)
    {
      IBufferedCipher cipher = CipherUtilities.GetCipher(Standards.DefEncryptionAES);
      KeyParameter keyParameter = new KeyParameter(aesKey);
      if (iv != null)
      {
        ICipherParameters parameters = new ParametersWithIV(keyParameter, iv);
        cipher.Init(forEncryption, parameters);
      }
      else
      {
        cipher.Init(forEncryption, keyParameter);
      }
      return cipher;
    }

    public static string AESEncryptData(string orgString, string key, string iv = "")
    {
      byte[] originalDataBytes = Standards.DefEncoding.GetBytes(orgString);
      byte[] aesKeyByteData = Standards.DefEncoding.GetBytes(key);
      byte[] ivDataBytes = null;
      if (!string.IsNullOrEmpty(iv))
      {
        ivDataBytes = Standards.DefEncoding.GetBytes(iv);
      }
      return Convert.ToBase64String(AESEncryptData(originalDataBytes, aesKeyByteData, ivDataBytes));
    }

    public static byte[] AESEncryptData(byte[] originalDataBytes, byte[] aesKeyByteData, byte[] iv = null)
    {
      bool isEncryption = true;

      MemoryStream originalDataStream = new MemoryStream(originalDataBytes, false);
      MemoryStream encryptedDataStream = new MemoryStream();
      IBufferedCipher aesCipher = AESCreateCipher(isEncryption, aesKeyByteData, iv);
      CipherStream cipherStream = new CipherStream(originalDataStream, aesCipher, null);

      int oneByte;
      while ((oneByte = cipherStream.ReadByte()) >= 0)
      {
        encryptedDataStream.WriteByte((byte)oneByte);
      }
      encryptedDataStream.Close();
      cipherStream.Close();

      return encryptedDataStream.ToArray();
    }

    public static string AESDecryptData(string encryptedString, string key, string iv = "")
    {
      byte[] encryptedDataBytes = Convert.FromBase64String(encryptedString);
      byte[] aesKeyByteData = Standards.DefEncoding.GetBytes(key);
      byte[] ivDataBytes = null;
      if (!string.IsNullOrEmpty(iv))
      {
        ivDataBytes = Standards.DefEncoding.GetBytes(iv);
      }
      return Standards.DefEncoding.GetString(AESDecryptData(encryptedDataBytes, aesKeyByteData, ivDataBytes));
    }

    public static byte[] AESDecryptData(byte[] encryptedDataBytes, byte[] aesKeyByteData, byte[] iv = null)
    {
      bool isEncryption = false;

      MemoryStream enryptedDataSream = new MemoryStream(encryptedDataBytes, false);
      MemoryStream decryptedDataStream = new MemoryStream();
      IBufferedCipher aesCipher = AESCreateCipher(isEncryption, aesKeyByteData, iv);
      CipherStream decodedCipherStream = new CipherStream(enryptedDataSream, aesCipher, null);

      int oneByte;
      while ((oneByte = decodedCipherStream.ReadByte()) >= 0)
      {
        decryptedDataStream.WriteByte((byte)oneByte);
      }

      decodedCipherStream.Close();
      decryptedDataStream.Close();

      return decryptedDataStream.ToArray();
    }
  }

}
