using System;
using FiverxLinkSecurityLib.Global;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace FiverxLinkSecurityLib.Security
{
  public class SignHelper
  {
    public static string SignData(string text, string pathPkcsCert, string password)
    {
      Pkcs12Store store = CertHelper.LadePkcsStore(pathPkcsCert, password);
      AsymmetricKeyParameter key = KeyHelper.GetPrivateKeyFromPkcs12Store(store);
      return SignData(text, key);
    }

    public static string SignData(string text, AsymmetricKeyParameter key)
    {
      ISigner signer = SignerUtilities.GetSigner(Standards.DefSigningAlgorythmus.ToString());
      signer.Init(true, key);
      byte[] bytes = Standards.DefEncoding.GetBytes(text);
      signer.BlockUpdate(bytes, 0, bytes.Length);
      byte[] signature = signer.GenerateSignature();
      string signedString = Convert.ToBase64String(signature);
      return signedString;
    }

    public static bool VerifySign(string text, string signatur, string pathx509Cert)
    {
      AsymmetricKeyParameter key = KeyHelper.GetPublicKeyFromX509Cert(pathx509Cert);
      return VerifySign(text, signatur, key);
    }

    public static bool VerifySign(string text, string signatur, AsymmetricKeyParameter key)
    {
      byte[] sourceSignaturB64 = Convert.FromBase64String(signatur);

      ISigner signer = SignerUtilities.GetSigner(Standards.DefSigningAlgorythmus.ToString());
      signer.Init(false, key);

      byte[] bytes = Standards.DefEncoding.GetBytes(text);

      signer.BlockUpdate(bytes, 0, bytes.Length);

      return signer.VerifySignature(sourceSignaturB64);
    }
  }
}
