using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using FiverxLinkSecurityLib.BouncyCastle;
using FiverxLinkSecurityLib.Global;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace FiverxLinkSecurityLib.Security
{
  public class KeyHelper
  {
    public enum KeyStrength
    {
      ks128,
      ks256,
      ks512,
      ks1024,
      ks2048,
      ks4096
    }

    public enum BlockSize
    {
      bs128,
      bs192,
      bs256
    }

    public static int GetSchluesselStaerke(KeyStrength keyStrength)
    {
      switch (keyStrength)
      {
        case KeyStrength.ks128:
          {
            return 128;
          }
        case KeyStrength.ks256:
          {
            return 256;
          }
        case KeyStrength.ks512:
          {
            return 512;
          }
        case KeyStrength.ks1024:
          {
            return 1024;
          }
        case KeyStrength.ks2048:
          {
            return 2048;
          }
        case KeyStrength.ks4096:
          {
            return 4096;
          }
        default:
          {
            return 2048;
          }
      }
    }

    public static int GetBlockSize(BlockSize blockSize)
    {
      switch (blockSize)
      {
        case BlockSize.bs128:
          {
            return 128;
          }
        case BlockSize.bs192:
          {
            return 192;
          }
        case BlockSize.bs256:
          {
            return 256;
          }
        default:
          {
            return 256;
          }
      }
    }

    public static AsymmetricKeyParameter GetPublicKeyFromDERFormat(string keyString)
    {
      AsymmetricKeyParameter key = null;

      byte[] byteArray = Standards.DefEncoding.GetBytes(keyString);
      using (MemoryStream stream = new MemoryStream(byteArray))
      {
        using (StreamReader streamreader = new StreamReader(stream, Standards.DefEncoding))
        {
          PemReader pemreader = new PemReader(streamreader);
          key = (AsymmetricKeyParameter)pemreader.ReadObject();
        }
      }
      return key;
    }

    public static AsymmetricKeyParameter GetPublicKeyFromPEMFormat(string keyString)
    {
      AsymmetricKeyParameter key = null;

      byte[] byteArray = Standards.DefEncoding.GetBytes(keyString);
      using (MemoryStream stream = new MemoryStream(byteArray))
      {
        using (StreamReader streamreader = new StreamReader(stream, Standards.DefEncoding))
        {
          PemReader pemreader = new PemReader(streamreader);
          X509Certificate cert = (X509Certificate)pemreader.ReadObject();
          key = cert.GetPublicKey();
        }
      }
      return key;
    }

    public static AsymmetricKeyParameter GetPrivateKeyFromDERFormat(string keyString)
    {
      AsymmetricKeyParameter key = null;

      byte[] byteArray = Standards.DefEncoding.GetBytes(keyString);
      using (MemoryStream stream = new MemoryStream(byteArray))
      {
        using (StreamReader streamreader = new StreamReader(stream, Standards.DefEncoding))
        {
          PemReader pemreader = new PemReader(streamreader);
          AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemreader.ReadObject();
          key = (AsymmetricKeyParameter)keyPair.Private;
        }
      }
      return key;
    }

    public static AsymmetricKeyParameter GetPrivateKeyFromPEMFormat(string keyString, string password)
    {
      AsymmetricKeyParameter key = null;

      byte[] byteArray = Standards.DefEncoding.GetBytes(keyString);
      using (MemoryStream stream = new MemoryStream(byteArray))
      {
        using (StreamReader streamreader = new StreamReader(stream, Standards.DefEncoding))
        {
          IPasswordFinder pFinder = new Password(password);
          PemReader pemreader = new PemReader(streamreader, pFinder);
          AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemreader.ReadObject();
          key = keyPair.Private;
        }
      }
      return key;
    }

    public static AsymmetricKeyParameter GetPublicKeyFromString(string keyString)
    {
      AsymmetricKeyParameter key = null;

      byte[] byteArray = Standards.DefEncoding.GetBytes(keyString);
      using (MemoryStream stream = new MemoryStream(byteArray))
      {
        using (StreamReader streamreader = new StreamReader(stream, Standards.DefEncoding))
        {
          PemReader pemreader = new PemReader(streamreader);
          key = (AsymmetricKeyParameter)pemreader.ReadObject();
        }
      }
      return key;
    }


    public static AsymmetricKeyParameter GetPrivateKeyFromString(string keyString)
    {
      AsymmetricKeyParameter key = null;

      byte[] byteArray = Standards.DefEncoding.GetBytes(keyString);
      using (MemoryStream stream = new MemoryStream(byteArray))
      {
        using (StreamReader streamreader = new StreamReader(stream, Standards.DefEncoding))
        {
          PemReader pemreader = new PemReader(streamreader);
          AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemreader.ReadObject();
          key = (AsymmetricKeyParameter)keyPair.Private;
        }
      }
      return key;
    }

    public static string GetKeyString(AsymmetricKeyParameter key)
    {
      string keyString = "";

      using (StringWriter stringWriter = new StringWriter())
      {
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(key);
        pemWriter.Writer.Flush();
        stringWriter.Close();
        keyString = stringWriter.ToString();
      }

      return keyString;
    }

    public static AsymmetricCipherKeyPair CreateAsymmetricKeyPair(KeyStrength keyStrength)
    {
      RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
      keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), GetSchluesselStaerke(keyStrength)));
      AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
      return keyPair;
    }

    public static void CreateAsymmetricKeyPair(KeyStrength keyStrength, out AsymmetricKeyParameter publicKey, out AsymmetricKeyParameter privateKey)
    {
      publicKey = null;
      privateKey = null;

      AsymmetricCipherKeyPair keyPair = CreateAsymmetricKeyPair(keyStrength);

      privateKey = keyPair.Private as AsymmetricKeyParameter;
      publicKey = keyPair.Public as AsymmetricKeyParameter;
    }

    public static AsymmetricKeyParameter GetPublicKeyFromX509Cert(string pfadZertifikat)
    {
      X509Certificate cert = CertHelper.Ladex509Certificate(pfadZertifikat);
      return GetPublicKeyFromX509Cert(cert);
    }

    public static AsymmetricKeyParameter GetPublicKeyFromX509Cert(X509Certificate cert)
    {
      return cert.GetPublicKey();
    }

    public static AsymmetricKeyParameter GetPublicKeyFromX509Cert(System.Security.Cryptography.X509Certificates.X509Certificate cert)
    {
      return PublicKeyFactory.CreateKey(cert.GetPublicKey());
    }

    public static AsymmetricKeyParameter GetPrivateKeyFromPkcsStore(string certPath, string passwort)
    {
      Pkcs12Store store = CertHelper.LadePkcsStore(certPath, passwort);
      return GetPrivateKeyFromPkcs12Store(store);
    }

    public static AsymmetricKeyParameter GetPublicKeyFromPkcsStore(string certPath, string passwort)
    {
      Pkcs12Store store = CertHelper.LadePkcsStore(certPath, passwort);
      return GetPublicKeyFromPkcsStore(store);
    }

    public static RSACryptoServiceProvider ConvertByteArrayToRSACryptoServiceProvider(byte[] keyArray)
    {
      AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(keyArray);
      return ConvertAsymmetricKeyParameterToRSACryptoServiceProvider(key);
    }

    public static RSACryptoServiceProvider ConvertAsymmetricKeyParameterToRSACryptoServiceProvider(AsymmetricKeyParameter key)
    {
      RSAParameters rsaParameters = new RSAParameters();
      if (!key.IsPrivate)
      {
        RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)key;
        rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
        rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
      }
      else
      {
        RsaPrivateCrtKeyParameters keyParams = (RsaPrivateCrtKeyParameters)key;
        rsaParameters = DotNetUtilities.ToRSAParameters(keyParams);
        CspParameters cspParameters = new CspParameters();
        RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(cspParameters);
      }
      RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
      rsa.ImportParameters(rsaParameters);
      return rsa;
    }

    public static RsaPrivateCrtKeyParameters GetPrivateKeyFromPkcs12Store(Pkcs12Store store)
    {
      RsaPrivateCrtKeyParameters keyParameters = null;

      foreach (string n in store.Aliases)
      {
        if (store.IsKeyEntry(n))
        {
          AsymmetricKeyEntry key = store.GetKey(n);

          if (key.Key.IsPrivate)
          {
            keyParameters = key.Key as RsaPrivateCrtKeyParameters;
          }
        }
      }

      return keyParameters;
    }

    public static AsymmetricKeyParameter GetPublicKeyFromPkcsStore(Pkcs12Store store)
    {
      AsymmetricKeyParameter keyParameter = null;

      foreach (string n in store.Aliases)
      {
        try
        {
          X509CertificateEntry cert = store.GetCertificate(n);
          keyParameter = (AsymmetricKeyParameter)cert.Certificate.GetPublicKey();
        }
        catch { }

        if (keyParameter != null)
        {
          break;
        }
      }

      return keyParameter;
    }

    public static List<string> GetAktivierungscodeCodeListe()
    {
      List<string> aktivierungscodeCodeListe = new List<string>();
      for (int i = 48; i <= 57; i++)
      {
        aktivierungscodeCodeListe.Add(Convert.ToChar(i).ToString());
      }
      for (int i = 65; i <= 90; i++)
      {
        aktivierungscodeCodeListe.Add(Convert.ToChar(i).ToString());
      }
      return aktivierungscodeCodeListe;
    }

    public static string CreateAktivierungsCode(List<string> aktivierungsCodeListe = null)
    {
      string aktivierungsCode = "";

      if (aktivierungsCodeListe == null)
      {
        aktivierungsCodeListe = GetAktivierungscodeCodeListe();
      }

      RNGCryptoServiceProvider csp = new RNGCryptoServiceProvider();
      byte[] numbers = new Byte[25];
      csp.GetBytes(numbers);

      byte min = Convert.ToByte(0);
      byte max = Convert.ToByte(aktivierungsCodeListe.Count - 1);

      // Die Zahlen umrechnen
      double divisor = 256F / (max - min + 1);
      if (min > 0 || max < 255)
      {
        string block = "";

        for (int i = 0; i < 20; i++)
        {
          block += aktivierungsCodeListe[(int)((numbers[i] / divisor) + min)];

          if (block.Length == 4)
          {
            int quersumme = 0;

            for (int j = 0; j < 4; j++)
            {
              if (j % 2 == 0)
              {
                quersumme += aktivierungsCodeListe.IndexOf(block[j].ToString()) * 2;
              }
              else
              {
                quersumme += aktivierungsCodeListe.IndexOf(block[j].ToString()) * 1;
              }
            }

            int moduloWert = quersumme % 36;

            aktivierungsCode += block + aktivierungsCodeListe[moduloWert];

            block = "";
          }

          if (aktivierungsCode.Length < 25)
          {
            aktivierungsCode += "-";
          }
        }
      }

      return aktivierungsCode;
    }

    public static bool VerifyAktivierungsCode(string aktivierungsCode, List<string> aktivierungsCodeListe = null)
    {
      if (aktivierungsCodeListe == null)
      {
        aktivierungsCodeListe = GetAktivierungscodeCodeListe();
      }

      aktivierungsCode.Replace("-", "");

      int quersumme = 0;
      int pos = 0;

      for (int i = 0; i < 25; i++)
      {
        if ((i + 1) % 5 == 0 && i > 0)
        {
          int moduloWert = quersumme % 36;

          if (!aktivierungsCodeListe[moduloWert].Equals(aktivierungsCode[i].ToString()))
          {
            return false;
          }

          quersumme = 0;
          pos = 0;
        }
        else
        {
          if (pos % 2 == 0)
          {
            quersumme += aktivierungsCodeListe.IndexOf(aktivierungsCode[i].ToString()) * 2;
          }
          else
          {
            quersumme += aktivierungsCodeListe.IndexOf(aktivierungsCode[i].ToString()) * 1;
          }

          pos++;
        }
      }

      return true;
    }

    public static string CreateAESKey(KeyStrength schluesselStaerke)
    {
      int anzahlZeichen = GetSchluesselStaerke(schluesselStaerke) / 8;
      return GeneriereZeichenfolge(anzahlZeichen);
    }

    public static string CreateAESIV(BlockSize blockSize)
    {
      int anzahlZeichen = GetBlockSize(blockSize) / 8;
      return GeneriereZeichenfolge(anzahlZeichen);
    }

    public static string CreateRSAPasswort(int anzahlZeichen)
    {
      return GeneriereZeichenfolge(anzahlZeichen);
    }

    public static string CreateRSAPasswort()
    {
      Random rnd = new Random();
      return CreateRSAPasswort(rnd.Next(15, 30));
    }

    private static string GeneriereZeichenfolge(int anzahlZeichen)
    {
      string generierteZeichenfolge = "";
      string zeichen = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw";
      Random rnd = new Random();
      for (int i = 0; i < anzahlZeichen; i++)
      {
        generierteZeichenfolge += (zeichen[rnd.Next(zeichen.Length)]);
      }
      return generierteZeichenfolge;
    }
  }
}
