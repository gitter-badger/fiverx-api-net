
using System.Xml;
using FiverxLinkSecurityLib.Schema.V0200;
using FiverxLinkSecurityLib.Security;
using FiveRxLinkSecurityLib.Global;
using FiveRxLinkSecurityLib.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
namespace FiverxLinkSecurityLib.Kommunikation.V0200
{
  public class FiveRxSecurityResponse
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
                                                Pkcs12Store clientKeyStore,
                                                string clientKeyStorePasswort,
                                                SecurityKonfiguration konfiguration,
                                                XmlDocument fachlicheAntwortXml = null)
    {
      rzeAntwort antwort = new rzeAntwort();
      antwort.hinweis = antwortHinweis;

      if (fachlicheAntwortXml != null)
      {
        X509Certificate clientCertificate = CertHelper.LadeX509CertificateFromPkcs12Store(clientKeyStore);
        XmlHelper.SignAndEncryptXml(fachlicheAntwortXml, clientKeyStore, clientKeyStorePasswort, konfiguration, clientCertificate);
        antwort.rzDatenBox = Standards.DefEncoding.GetBytes(ParseHelper.ConvertXmlDocumentToString(fachlicheAntwortXml));
      }

      return antwort;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="antwort"></param>
    /// <param name="clientKeyStore"></param>
    /// <param name="clientKeyStorePasswort"></param>
    /// <param name="istEntschluesselungErfolgreich"></param>
    /// <param name="istSignaturValide"></param>
    /// <param name="istRohdatenTransfer"></param>
    /// <returns></returns>
    public static string VerifiziereRzeAntwort(rzeAntwort antwort,
                                               Pkcs12Store clientKeyStore,
                                               string clientKeyStorePasswort,
                                               out bool istEntschluesselungErfolgreich,
                                               out bool istSignaturValide,
                                               out bool istRohdatenTransfer)
    {
      istEntschluesselungErfolgreich = false;
      istSignaturValide = false;
      istRohdatenTransfer = false;

      string xmlAsString = null;

      XmlHelper.DecryptVerifyXMLAndGetRawData(antwort.rzDatenBox,
                                              clientKeyStore,
                                              clientKeyStorePasswort,
                                              clientKeyStore,
                                              clientKeyStorePasswort,
                                              out istEntschluesselungErfolgreich,
                                              out istSignaturValide,
                                              out istRohdatenTransfer,
                                              out xmlAsString);

      return xmlAsString;
    }
  }
}
