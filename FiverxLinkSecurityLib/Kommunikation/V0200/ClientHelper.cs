using System.Xml;
using FiverxLinkSecurityLib.Global;
using FiverxLinkSecurityLib.Schema.V0200;
using FiverxLinkSecurityLib.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace FiverxLinkSecurityLib.Kommunikation.V0200
{
  public class ClientHelper
  {
    /// <summary>
    /// Erstellt ein Objekt vom Typ rzeAnfrage für die Methode verarbeiteAuftrag. Hier erfolgt die Zusammenführung
    /// der ApothekenInformation mit den fachlichen Daten. Die fachlichen Daten werden auf dem obersten Knoten des XML
    /// Dokument signiert und verschlüsselt und als Byte Array in dem Anfrage Objekt abgelegt.
    /// </summary>
    /// <param name="fachlicheAnfrageXml">Xml nach dem Schema RzeRezept Version xxxx</param>
    /// <param name="rzkdnr">Kundennummer der Apotheke</param>
    /// <param name="apoIk">ApothekenIK</param>
    /// <param name="apoInformation">Information zur Apotheke</param>
    /// <param name="apoLogMethode">Methode im fachlichen Sinne, welche die Apotheke beabsichtigt anzusprechen</param>
    /// <param name="softwarehersteller">Hersteller der Warenwirtschaft</param>
    /// <param name="softwarename">Name der Warenwirtschaft</param>
    /// <param name="softwareversion">Version der Warenwirtschaft</param>
    /// <param name="clientKeyStore">KeyStore mit dessen Informationen das XML verschlüsselt werden soll</param>
    /// <param name="clientKeyStorePasswort">Passwort zum KeyStore des Clients</param>
    /// <param name="konfiguration">Sicherheitskonfiguration für die Verschlüsselung</param>
    /// <param name="rzCertificate">Zertifikat des Rechenzentrums</param>
    /// <returns></returns>
    public static rzeAnfrage ErstelleRzeAnfrageObjekt(XmlDocument fachlicheAnfrageXml,
                                                      string rzkdnr,
                                                      string apoIk,
                                                      string apoInformation,
                                                      string apoLogMethode,
                                                      string softwarehersteller,
                                                      string softwarename,
                                                      string softwareversion,
                                                      Pkcs12Store clientKeyStore,
                                                      string clientKeyStorePasswort,
                                                      SecurityKonfiguration konfiguration,
                                                      X509Certificate rzCertificate)
    {
      rzeAnfrage anfrage = new rzeAnfrage();

      XmlHelper.SignAndEncryptXml(fachlicheAnfrageXml,
                                  clientKeyStore,
                                  clientKeyStorePasswort,
                                  konfiguration,
                                  rzCertificate);

      //Bilde das RzeAnfrage Objekt:
      apoInformation apoInfoObjekt = new apoInformation();
      apoInfoObjekt.rzKdNr = rzkdnr;
      apoInfoObjekt.apoIk = apoIk;
      apoInfoObjekt.apoInfo = apoInformation;
      apoInfoObjekt.apoLogMethode = apoLogMethode;
      apoInfoObjekt.apoSwHersteller = softwarehersteller;
      apoInfoObjekt.apoSwName = softwarename;
      apoInfoObjekt.apoSwVersion = softwareversion;
      anfrage.apoInformation = apoInfoObjekt;
      anfrage.rzDatenBox = Standards.DefEncoding.GetBytes(ParseHelper.ConvertXmlDocumentToString(fachlicheAnfrageXml));

      return anfrage;
    }


    /// <summary>
    /// Erstellt ein Objekt vom Typ rzeLadeRzSicherheitsmerkmalAnfrage, welches notwendig ist um
    /// die Methode ladeRzSicherheitsmerkmale anzusprechen
    /// </summary>
    /// <param name="fachlicheAnfrageXml">Xml nach dem Schema RzeRezept Version xxxx</param>
    /// <param name="rzkdnr">Kundennummer der Apotheke</param>
    /// <param name="apoIk">ApothekenIK</param>
    /// <param name="apoInformation">Information zur Apotheke</param>
    /// <param name="apoLogMethode">Methode im fachlichen Sinne, welche die Apotheke beabsichtigt anzusprechen</param>
    /// <param name="softwarehersteller">Hersteller der Warenwirtschaft</param>
    /// <param name="softwarename">Name der Warenwirtschaft</param>
    /// <param name="softwareversion">Version der Warenwirtschaft</param>
    /// <returns></returns>
    public static rzeLadeRzSicherheitsmerkmaleAnfrage ErstelleRzeLadeSicherheitsmerkmalAnfrage(string rzkdnr,
                                                                                               string apoIk,
                                                                                               string apoInformation,
                                                                                               string apoLogMethode,
                                                                                               string softwarehersteller,
                                                                                               string softwarename,
                                                                                               string softwareversion)
    {
      apoInformation apoInfoObjekt = new apoInformation();
      apoInfoObjekt.rzKdNr = rzkdnr;
      apoInfoObjekt.apoIk = apoIk;
      apoInfoObjekt.apoInfo = apoInformation;
      apoInfoObjekt.apoLogMethode = apoLogMethode;
      apoInfoObjekt.apoSwHersteller = softwarehersteller;
      apoInfoObjekt.apoSwName = softwarename;
      apoInfoObjekt.apoSwVersion = softwareversion;

      rzeLadeRzSicherheitsmerkmaleAnfrage anfrage = new rzeLadeRzSicherheitsmerkmaleAnfrage();
      anfrage.apoInformation = apoInfoObjekt;
      return anfrage;
    }

    /// <summary>
    /// ERstellt ein Objekt vom Typ rzeLadeRzSecurityVersionAnfrage, welches notwendig ist um die Methode
    /// ladeRzSecurityVersion anzusprechen
    /// </summary>
    /// <param name="fachlicheAnfrageXml">Xml nach dem Schema RzeRezept Version xxxx</param>
    /// <param name="rzkdnr">Kundennummer der Apotheke</param>
    /// <param name="apoIk">ApothekenIK</param>
    /// <param name="apoInformation">Information zur Apotheke</param>
    /// <param name="apoLogMethode">Methode im fachlichen Sinne, welche die Apotheke beabsichtigt anzusprechen</param>
    /// <param name="softwarehersteller">Hersteller der Warenwirtschaft</param>
    /// <param name="softwarename">Name der Warenwirtschaft</param>
    /// <param name="softwareversion">Version der Warenwirtschaft</param>
    /// <returns></returns>
    public static rzeLadeRzSecurityVersionAnfrage ErstelleRzeLadeRzSecurityVersionAnfrage(string rzkdnr,
                                                                                               string apoIk,
                                                                                               string apoInformation,
                                                                                               string apoLogMethode,
                                                                                               string softwarehersteller,
                                                                                               string softwarename,
                                                                                               string softwareversion)
    {
      apoInformation apoInfoObjekt = new apoInformation();
      apoInfoObjekt.rzKdNr = rzkdnr;
      apoInfoObjekt.apoIk = apoIk;
      apoInfoObjekt.apoInfo = apoInformation;
      apoInfoObjekt.apoLogMethode = apoLogMethode;
      apoInfoObjekt.apoSwHersteller = softwarehersteller;
      apoInfoObjekt.apoSwName = softwarename;
      apoInfoObjekt.apoSwVersion = softwareversion;

      rzeLadeRzSecurityVersionAnfrage anfrage = new rzeLadeRzSecurityVersionAnfrage();
      anfrage.apoInformation = apoInfoObjekt;
      return anfrage;
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
    public static string VerifiziereServerAntwort(byte[] antwort,
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

      XmlHelper.DecryptVerifyXMLAndGetRawData(antwort,
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
