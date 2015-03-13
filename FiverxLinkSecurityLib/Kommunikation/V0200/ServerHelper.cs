
using System.Xml;
using FiverxLinkSecurityLib.Schema.V0200;
using FiverxLinkSecurityLib.Security;
using FiveRxLinkSecurityLib.Global;
using FiveRxLinkSecurityLib.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
namespace FiverxLinkSecurityLib.Kommunikation.V0200
{
  public class ServerHelper
  {
    /// <summary>
    /// 
    /// </summary>
    /// <param name="antwortHinweis"></param>
    /// <param name="clientKeyStore"></param>
    /// <param name="clientKeyStorePasswort"></param>
    /// <param name="konfiguration"></param>
    /// <param name="fachlicheAntwortXml"></param>
    /// <returns></returns>
    public static rzeAntwort ErstelleRzeAntwort(string antwortHinweis,
                                                X509Certificate clientCertificate,
                                                Pkcs12Store rzKeyStore,
                                                string rzKeyStorePasswort,
                                                SecurityKonfiguration konfiguration,
                                                XmlDocument fachlicheAntwortXml = null)
    {
      rzeAntwort antwort = new rzeAntwort();
      antwort.hinweis = antwortHinweis;

      if (fachlicheAntwortXml != null)
      {
        XmlHelper.SignAndEncryptXml(fachlicheAntwortXml, rzKeyStore, rzKeyStorePasswort, konfiguration, clientCertificate);
        antwort.rzDatenBox = Standards.DefEncoding.GetBytes(ParseHelper.ConvertXmlDocumentToString(fachlicheAntwortXml));
      }

      return antwort;
    }

    /// <summary>
    /// Entschlüsselt die RzeAnfrage, verfiziert die Signatur und das Zerifikat mit dem die Signatur erstellt wurde.
    /// Zudem wird aus dem signierten XML das urprüngliche Rohdaten XML gewonnen
    /// </summary>
    /// <param name="anfrage">Anfrage als rzeAnfrage</param>
    /// <param name="rzKeyStore">KeyStore des RZs</param>
    /// <param name="rzKeyStorePasswort">Passwort zum KeyStore des RZs</param>
    /// <param name="clientKeyStore">KeyStore des Clients</param>
    /// <param name="clientKeyStorePasswort">Passwort zum KeyStore des Clients</param>
    /// <param name="istEntschluesselungErfolgreich">Rückgabe ob die Entschlüsselung funktioniert hat</param>
    /// <param name="istSignaturValide">Rückgabe ob die Signatur und das Zertifikat in Ordnung waren</param>
    /// <param name="istRohdatenTransfer">Rückgabe ob das signierte XML in die Rohdaten umgewandelt werden konnte</param>
    /// <returns></returns>
    public static string VerifiziereClientAnfrage(byte[] anfrage,
                                                  Pkcs12Store rzKeyStore,
                                                  string rzKeyStorePasswort,
                                                  out bool istEntschluesselungErfolgreich,
                                                  out bool istSignaturValide,
                                                  out bool istRohdatenTransfer)
    {
      istEntschluesselungErfolgreich = false;
      istSignaturValide = false;
      istRohdatenTransfer = false;

      string xmlAsString = null;

      XmlHelper.DecryptVerifyXMLAndGetRawData(anfrage,
                                              rzKeyStore,
                                              rzKeyStorePasswort,
                                              out istEntschluesselungErfolgreich,
                                              out istSignaturValide,
                                              out istRohdatenTransfer,
                                              out xmlAsString);

      return xmlAsString;
    }
  }
}
