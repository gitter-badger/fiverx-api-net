
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
      XmlEncryptionAesAlgorithmus = "XmlEncAES256Url";
      XmlEncryptionUseOAEP = true;
      XmlEncryptionRsaAlgorithmus = "XmlEncRSAOAEPUrl";
    }
  }
}
