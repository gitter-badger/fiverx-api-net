
namespace FiverxLinkSecurityLib.Security
{
  public class SecurityKonfiguration
  {
    public bool XmlEncryptionNurInhaltDesZuVerschluesselndenKnotensVerschluesseln { get; set; }
    public int XmlEncryptionAesKeySize { get; set; }
    public string XmlEncryptionAesAlgorithmus { get; set; }
    public bool XmlEncryptionUseOAEP { get; set; }
    public string XmlEncryptionRsaAlgorithmus { get; set; }

    public SecurityKonfiguration()
    {
      //TODO: Vorläufe Vorabdefinition, Verlagerung in app.Config o. ähnliches und Anpassung an gewähten Algorithmus Auswahl Standard

      XmlEncryptionNurInhaltDesZuVerschluesselndenKnotensVerschluesseln = true;
      XmlEncryptionAesKeySize = 256;
      XmlEncryptionAesAlgorithmus = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
      XmlEncryptionUseOAEP = true;
      XmlEncryptionRsaAlgorithmus = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    }
  }
}
