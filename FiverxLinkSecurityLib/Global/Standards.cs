using System.Text;

namespace FiveRxLinkSecurityLib.Global
{
  public class Standards
  {
    public enum HashType
    {
      SHA1withDSA,
      SHA1withECDSA,
      SHA224withECDSA,
      SHA256withECDSA,
      SHA384withECDSA,
      SHA512withECDSA,
      MD2withRSA,
      MD5withRSA,
      SHA1withRSA,
      SHA224withRSA,
      SHA256withRSA,
      SHA384withRSA,
      SHA512withRSA,
      RIPEMD160withRSA,
      RIPEMD128withRSA,
      RIPEMD256withRSA,
    }

    private static string _defEncrytionRSA = "RSA/ECB/PKCS1Padding";
    public static string DefEncryptionRSA
    {
      get
      {
        return _defEncrytionRSA; ;
      }
      set
      {
        _defEncrytionRSA = value;
      }
    }


    private static string _defEncryptionAES = "AES/CBC/PKCS7Padding";
    public static string DefEncryptionAES
    {
      get
      {
        return _defEncryptionAES;
      }
      set
      {
        _defEncryptionAES = value;
      }
    }

    private static Encoding _defEncoding = Encoding.GetEncoding("ISO-8859-15");
    public static Encoding DefEncoding
    {
      get
      {
        return _defEncoding;
      }
      set
      {
        _defEncoding = value;
      }
    }

    public static HashType _defSigningAlgorythmus = HashType.SHA256withRSA;
    public static HashType DefSigningAlgorythmus
    {
      get
      {
        return _defSigningAlgorythmus;
      }
      set
      {
        _defSigningAlgorythmus = value;
      }
    }

  }
}
