
using System;
using System.IO;
using System.Xml;
using FiverxLinkSecurityLib.Global;
using FiverxLinkSecurityLib.Kommunikation.V0200;
using FiverxLinkSecurityLib.Schema.V0200;
using FiverxLinkSecurityLib.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace FiverxLinkSecurityTestClient
{
  public class Demo
  {
    static string zertpfad = @"C:\TempFiveRx";

    static string rzPasswort = "testr";
    static string rzCertAusteller = "TestRZ";
    static string rzCertDateiname = "TestDotNetRZZertifikat";

    static string clientPasswort = "testc";
    static string clientAntragsteller = "TestClient";
    static string clientCertDateiname = "TestDotNetClientZertifikat";

    static string testXmlAnfrage = @"<Request><data>Dies ist eine Anfrage an den Server</data></Request>";
    static string testXmlAntwort = @"<Response><data>Dies ist eine Antwort an den Client</data></Response>";

    //static string fiveRxServiceAdresse = @"http://ars-fiverx.de:80/FiveRxLinkSecurityService.asmx";
    //static string fiveRxServiceAdresse = @"http://ars-fiverx.de:8555/FiveRxLinkSecurityService.asmx";
    //static string fiveRxServiceAdresse = @"https://192.168.38.214:400/FiveRxLinkSecurityService.asmx";
    static string fiveRxServiceAdresse = @"http://localhost:49439/FiveRxLinkSecurityService.asmx";
    static string fiveRxServiceAdresseNARZ = @"http://62.159.158.141/FiverxProductiveTest/FiverxLinkSecurityService";

    static string pfadAnfrageladeRzVersion = @"C:\TempFiveRx\ladeRzDienste.txt";


    /// <summary>
    /// Demo zur Erstellung des Serverzertifikates, Laden in den Zertifikatsspeicher, Laden aus dem Zertifikatsspeicher,
    /// Konvertierung in Base64String, Konvertierung aus Base64String
    /// </summary>
    /// <param name="mitZertifikatErstellung"></param>
    public static void DemoServerZertifikat(bool mitZertifikatErstellung)
    {
      //Erstellen eines Serverzertifikates:
      string passwort = rzPasswort;
      X509Certificate rzCertificate = null;
      Pkcs12Store rzKeyStore = null;

      if (mitZertifikatErstellung)
      {
        //Zertikat und KeyStore erstellen:
        rzCertificate = CertHelper.CreateCertificateAndKeyStore(FiverxLinkSecurityLib.Global.Standards.HashType.SHA256withRSA,
                                                                rzCertAusteller,
                                                                rzCertAusteller,
                                                                ref passwort,
                                                                out rzKeyStore,
                                                                DateTime.Now,
                                                                DateTime.Now.AddYears(1),
                                                                KeyHelper.KeyStrength.ks2048,
                                                                zertpfad,
                                                                rzCertDateiname,
                                                                true,
                                                                true,
                                                                true);

        //Laden des Serverzertifikates in den lokalen Maschinenzertifikatsspeicher:
        CertHelper.LadeX509CaZertifikatInMaschinenStore(rzCertificate, rzPasswort);
      }

      //Laden des Serverzertifikates aus dem lokalen Maschinenzertifikatsspeicher:
      X509Certificate certAusMaschinenspeicher = CertHelper.LadeX509AusMaschinenStore(rzCertAusteller);

      //Umwandlung des Zertifikates in Base64String (Serverseite):
      string base64StringCertificate = CertHelper.ConvertX509ToBase64String(certAusMaschinenspeicher);

      //Umwandlung des Zertifikates im Base64 Format in ein ZertifkatObjekt (Clientseite, hier nur zum Test):
      X509Certificate certAusBase64String = CertHelper.ConvertBase64StringToX509Certificate(base64StringCertificate);
    }


    /// <summary>
    /// Erstellung eines Clientzertifikat signiert durch CA Zertifikat, Erstellung des zugehörigen KeyStores,
    /// Konvertierung des KeyStores in Base64, Konvertierung eines Base64 KeyStores in KeyStoreObjekt
    /// </summary>
    public static void DemoClientZertifikat()
    {
      string passwort = clientPasswort;
      X509Certificate clientCertificate = null;
      Pkcs12Store clientKeyStore = null;

      //Laden des KeyStores des ServerZertifikates:
      Pkcs12Store caKeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + rzCertDateiname + ".pfx", rzPasswort);

      //Laden des ServerZertifikates:
      X509Certificate caCertifikate = CertHelper.LadeX509AusMaschinenStore(rzCertAusteller);

      //Erstellen des Clientzertifikates:
      clientCertificate = CertHelper.CreateClientCertificateAndKeyStore(caKeyStore,
                                                                        caCertifikate,
                                                                        FiverxLinkSecurityLib.Global.Standards.HashType.SHA256withRSA,
                                                                        clientAntragsteller,
                                                                        rzCertAusteller,
                                                                        ref passwort,
                                                                        out clientKeyStore,
                                                                        DateTime.Now,
                                                                        DateTime.Now.AddMonths(3),
                                                                        KeyHelper.KeyStrength.ks2048,
                                                                        zertpfad,
                                                                        clientCertDateiname,
                                                                        true,
                                                                        true,
                                                                        true);

      //Konvertierung des Client KeyStores in Base64 String für Übertragung
      string pkcsStoreBase64Formated = CertHelper.ConvertPkcs12ToBase64String(clientKeyStore, clientPasswort);

      //Rückkonvertierung in KeyStore aus Base64 String
      Pkcs12Store clientKeyStoreTrans = CertHelper.ConvertBase64StringToPKCSKeyStore(pkcsStoreBase64Formated, clientPasswort);
    }

    /// <summary>
    /// Laden der Zertifikate, Erstellen eines XML Objektes der Form rzeAnfrage, Signierung und Verschlüsselung des Objektes,
    /// und Entschlüsselung und Prüfung der Signatur
    /// </summary>
    public static void DemoRzeAnfrage()
    {
      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Client Seite:
      //----------------------------------------------------------------------------------------------------------------------------

      //Laden des Client KeyStores:
      Pkcs12Store clientkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      //Laden des Server Zerfifikats (üblich vom Server geladen per Webservice):
      X509Certificate caCertifikate = CertHelper.Ladex509Certificate(zertpfad + "\\" + rzCertDateiname + ".der");

      //Laden des fachliches Dokuments
      XmlDocument fachlichesDokumentClient = new XmlDocument();
      fachlichesDokumentClient.PreserveWhitespace = true;
      fachlichesDokumentClient.LoadXml(testXmlAnfrage);

      //Generierung des Serviceanfrage:
      rzeAnfrage anfrage = ClientHelper.ErstelleRzeAnfrageObjekt(fachlichesDokumentClient,
                                                                 "1111",
                                                                 "111111111",
                                                                 "testapo",
                                                                 "testmethode",
                                                                 "testhersteller",
                                                                 "testsoftware",
                                                                 "testversion",
                                                                  clientkeyStore,
                                                                  clientPasswort,
                                                                  new SecurityKonfiguration(),
                                                                  caCertifikate);



      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Server Seite:
      //----------------------------------------------------------------------------------------------------------------------------

      //Laden des Server KeyStores:
      Pkcs12Store rzKeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + rzCertDateiname + ".pfx", rzPasswort);

      //Überprüfung ob Signatur in Ordnung ist:
      bool istEntschluesselungErfolgreich;
      bool istSignaturKonfirm;
      bool istSigniertesXmlValide;

      X509Certificate signatureCertificate;

      string fachlicherRohString = ServerHelper.VerifiziereClientAnfrage(anfrage.rzDatenBox,
                                                                         rzKeyStore,
                                                                         rzPasswort,
                                                                         out istEntschluesselungErfolgreich,
                                                                         out istSignaturKonfirm,
                                                                         out istSigniertesXmlValide,
                                                                         out signatureCertificate);


      //Weitere Verarbeitung durch Fachlichen Service -->

    }

    /// <summary>
    /// Laden der Zertifikate, Erstellen eines XML Objektes der Form rzeAntwort, Signierung und Verschlüsselung des Objektes,
    /// und Entschlüsselung und Prüfung der Signatur
    /// </summary>
    public static void DemoRzeAntwort()
    {
      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Server Seite:
      //----------------------------------------------------------------------------------------------------------------------------

      // --> Antwort vom fachlichen Service 
      XmlDocument antwortFachlicherService = new XmlDocument();
      antwortFachlicherService.LoadXml(testXmlAntwort);

      //Laden des Server KeyStores:
      Pkcs12Store serverSitesRzkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + rzCertDateiname + ".pfx", rzPasswort);

      //Laden des Client Zerfifikats:
      X509Certificate serverSiteClientCertificate = CertHelper.Ladex509Certificate(zertpfad + "\\" + clientCertDateiname + ".der");

      rzeAntwort serverAntwort = ServerHelper.ErstelleRzeAntwort("kein Hinweis vorhanden",
                                                                           serverSiteClientCertificate,
                                                                           serverSitesRzkeyStore,
                                                                           rzPasswort,
                                                                           new SecurityKonfiguration(),
                                                                           antwortFachlicherService);

      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Client Seite:
      //----------------------------------------------------------------------------------------------------------------------------


      Pkcs12Store clientSiteClientKeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      //Überprüfung ob Signatur in Ordnung ist:
      bool istEntschluesselungErfolgreich;
      bool istSignaturValide;
      bool istSigniertesXmlValide;
      X509Certificate signatureCertificate;

      string xmlAsString = ClientHelper.VerifiziereServerAntwort(serverAntwort.rzDatenBox,
                                                                 clientSiteClientKeyStore,
                                                                 clientPasswort,
                                                                 out istEntschluesselungErfolgreich,
                                                                 out istSignaturValide,
                                                                 out istSigniertesXmlValide,
                                                                 out signatureCertificate);

    }

    public static void DemoServiceAnfrageVerarbeiteAuftrag()
    {
      //Laden des Client KeyStores:
      Pkcs12Store clientkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      rzeLadeRzZertifikatAntwort serviceZertifikatAntwort;

      //Laden des RzZertifikates:
      using (FiverxLinkSecurityLib.FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient client =
                SecurityServiceComHelper.GetFiveRxServiceSecurityClient(fiveRxServiceAdresse, clientkeyStore, clientPasswort))
      {
        FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzZertifikatResponse responseladeZertifikat =
            client.ladeRzZertifikat(new FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzZertifikatRequest());

        serviceZertifikatAntwort = ParseHelper.GetObjectFromXML<rzeLadeRzZertifikatAntwort>(responseladeZertifikat.ladeRzZertifikatResponseMsg.rzeAusgabeDaten);
      }

      X509Certificate caCertifikate = CertHelper.ConvertByteArrayToX509Certificate(serviceZertifikatAntwort.rzZertifikat);

      //Laden des fachliches Dokuments
      XmlDocument fachlichesDokumentClient = new XmlDocument();
      fachlichesDokumentClient.LoadXml(ParseHelper.ReadTextFromFile(pfadAnfrageladeRzVersion));

      //Generierung des Serviceanfrage:
      rzeAnfrage anfrage = ClientHelper.ErstelleRzeAnfrageObjekt(fachlichesDokumentClient,
                                                                 "9998",
                                                                 "303706931",
                                                                 "Testapotheke FiveRxSecurity",
                                                                 "ladeRzVersion",
                                                                 "Musterhersteller",
                                                                 "Mustersoftware",
                                                                 "Musterversion",
                                                                 clientkeyStore,
                                                                 clientPasswort,
                                                                 new SecurityKonfiguration(),
                                                                 caCertifikate);

      //anfrage.rzDatenBox =  Standards.DefEncoding.GetBytes(ParseHelper.ReadTextFromFile(zertpfad + "\\test.txt"));

      FiverxLinkSecurityLib.FiveRxSecurityService.verarbeiteAuftragResponse response;

      using (FiverxLinkSecurityLib.FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient client =
                SecurityServiceComHelper.GetFiveRxServiceSecurityClient(fiveRxServiceAdresse, clientkeyStore, clientPasswort))
      {
        FiverxLinkSecurityLib.FiveRxSecurityService.verarbeiteAuftragRequest request = new FiverxLinkSecurityLib.FiveRxSecurityService.verarbeiteAuftragRequest();
        request.verarbeiteAuftragRequestMsg = new FiverxLinkSecurityLib.FiveRxSecurityService.zweiParameterRequestMsg();
        request.verarbeiteAuftragRequestMsg.rzeEingabeDaten = ParseHelper.GetStringFromXMLObject<rzeAnfrage>(anfrage);
        request.verarbeiteAuftragRequestMsg.rzeLadeRzSecurityVersion = "Test";

        response = client.verarbeiteAuftrag(request);

        client.Close();
      }

      //Überprüfung ob Signatur in Ordnung ist:
      bool istEntschluesselungErfolgreich;
      bool istSignaturValide;
      bool istSigniertesXmlValide;
      X509Certificate signatureCertificate;

      rzeAntwort serverAntwort = ParseHelper.GetObjectFromXML<rzeAntwort>(response.verarbeiteAuftragResponseMsg.rzeAusgabeDaten);

      string xmlAsString = ClientHelper.VerifiziereServerAntwort(serverAntwort.rzDatenBox,
                                                                 clientkeyStore,
                                                                 clientPasswort,
                                                                 out istEntschluesselungErfolgreich,
                                                                 out istSignaturValide,
                                                                 out istSigniertesXmlValide,
                                                                 out signatureCertificate);
    }

    public static void DemoServiceAnfrageLadeSicherheitsmerkmale()
    {
      //Laden des Client KeyStores:
      Pkcs12Store clientkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      rzeLadeRzSicherheitsmerkmaleAnfrage anfrage = ClientHelper.ErstelleRzeLadeSicherheitsmerkmalAnfrage("9998",
                                                                                                          "303706931",
                                                                                                          "Testapotheke FiveRxSecurity",
                                                                                                          "ladeRzVersion",
                                                                                                          "Musterhersteller",
                                                                                                          "Mustersoftware",
                                                                                                          "Musterversion");

      FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse antwort = null;

      using (FiverxLinkSecurityLib.FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient client =
                SecurityServiceComHelper.GetFiveRxServiceSecurityClient(fiveRxServiceAdresse, clientkeyStore, clientPasswort))
      {
        FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest request =
          new FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest();
        request.ladeRzSicherheitsmerkmaleRequestMsg = new FiverxLinkSecurityLib.FiveRxSecurityService.zweiParameterRequestMsg();
        request.ladeRzSicherheitsmerkmaleRequestMsg.rzeEingabeDaten = ParseHelper.GetStringFromXMLObject<rzeLadeRzSicherheitsmerkmaleAnfrage>(anfrage);
        antwort = client.ladeRzSicherheitsmerkmale(request);
      }

      rzeLadeRzSicherheitsmerkmaleAntwort sicherheitsmerkmale = ParseHelper.GetObjectFromXML<rzeLadeRzSicherheitsmerkmaleAntwort>(antwort.ladeRzSicherheitsmerkmaleResponseMsg.rzeAusgabeDaten);
    }

    public static void DemoServiceAnfrageLadeRzSecurityVersion()
    {
      Pkcs12Store clientkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      rzeLadeRzSecurityVersionAnfrage anfrage = ClientHelper.ErstelleRzeLadeRzSecurityVersionAnfrage("9998",
                                                                                                  "303706931",
                                                                                                  "Testapotheke FiveRxSecurity",
                                                                                                  "ladeRzVersion",
                                                                                                  "Musterhersteller",
                                                                                                  "Mustersoftware",
                                                                                                  "Musterversion");

      FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzSecurityVersionResponse antwort = null;

      using (FiverxLinkSecurityLib.FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient client =
                SecurityServiceComHelper.GetFiveRxServiceSecurityClient(fiveRxServiceAdresse, clientkeyStore, clientPasswort))
      {
        FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzSecurityVersionRequest request =
          new FiverxLinkSecurityLib.FiveRxSecurityService.ladeRzSecurityVersionRequest();
        request.ladeRzSecurityVersionRequestMsg = new FiverxLinkSecurityLib.FiveRxSecurityService.einParameterRequestMsg();
        request.ladeRzSecurityVersionRequestMsg.rzeEingabeDaten = ParseHelper.GetStringFromXMLObject<rzeLadeRzSecurityVersionAnfrage>(anfrage);
        antwort = client.ladeRzSecurityVersion(request);
      }

      rzeLadeRzSecurityVersionAntwort securityVersion = ParseHelper.GetObjectFromXML<rzeLadeRzSecurityVersionAntwort>(antwort.ladeRzSecurityVersionResponseMsg.rzeAusgabeDaten);
    }
  }
}
