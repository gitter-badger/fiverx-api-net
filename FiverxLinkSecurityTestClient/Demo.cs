
using System;
using System.Xml;
using FiverxLinkSecurityLib.Kommunikation.V0200;
using FiverxLinkSecurityLib.Schema.V0200;
using FiverxLinkSecurityLib.Security;
using FiveRxLinkSecurityLib.Security;
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
        rzCertificate = CertHelper.CreateCertificateAndKeyStore(FiveRxLinkSecurityLib.Global.Standards.HashType.SHA256withRSA,
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
                                                                        FiveRxLinkSecurityLib.Global.Standards.HashType.SHA256withRSA,
                                                                        clientAntragsteller,
                                                                        rzCertAusteller,
                                                                        ref passwort,
                                                                        out clientKeyStore,
                                                                        DateTime.Now,
                                                                        DateTime.Now.AddYears(1),
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
    /// Laden de
    /// </summary>
    public static void DemoServiceAnfrage()
    {
      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Client Seite:
      //----------------------------------------------------------------------------------------------------------------------------

      //Laden des Client KeyStores:
      Pkcs12Store clientkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      //Laden des Server Zerfifikats (üblich vom Server geladen per Webservice):
      X509Certificate caCertifikate = CertHelper.LadeX509AusMaschinenStore(rzCertAusteller);

      //Laden des fachliches Dokuments
      XmlDocument fachlichesDokumentClient = new XmlDocument();
      fachlichesDokumentClient.LoadXml(testXmlAnfrage);



      //Generierung des Serviceanfrage:
      rzeAnfrage anfrage = FiveRxSecurityRequest.ErstelleRzeAnfrage(fachlichesDokumentClient,
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
      Pkcs12Store caKeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + rzCertDateiname + ".pfx", rzPasswort);

      //Überprüfung ob Signatur in Ordnung ist:
      bool istEntschluesselungErfolgreich;
      bool istSignaturKonfirm;
      bool istSigniertesXmlValide;

      string fachlicherRohString = FiveRxSecurityRequest.VerifiziereRzeAnfrage(anfrage,
                                                                       caKeyStore,
                                                                       rzPasswort,
                                                                       clientkeyStore,
                                                                       clientPasswort,
                                                                       out istEntschluesselungErfolgreich,
                                                                       out istSignaturKonfirm,
                                                                       out istSigniertesXmlValide);


      //Weitere Verarbeitung durch Fachlichen Service -->

    }

    public static void DemoServiceAntwort()
    {
      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Server Seite:
      //----------------------------------------------------------------------------------------------------------------------------

      // --> Antwort vom fachlichen Service 
      XmlDocument antwortFachlicherService = new XmlDocument();
      antwortFachlicherService.LoadXml(testXmlAntwort);

      //Laden des Client KeyStores:
      Pkcs12Store clientkeyStore = CertHelper.LadePkcsStore(zertpfad + "\\" + clientCertDateiname + ".pfx", clientPasswort);

      //Laden des Server Zerfifikats
      X509Certificate caCertifikate = CertHelper.LadeX509AusMaschinenStore(rzCertAusteller);

      rzeAntwort serverAntwort = FiveRxSecurityResponse.ErstelleRzeAntwort("kein Hinweis vorhanden", clientkeyStore, clientPasswort, new SecurityKonfiguration(), antwortFachlicherService);

      //----------------------------------------------------------------------------------------------------------------------------
      //Auf Client Seite:
      //----------------------------------------------------------------------------------------------------------------------------

      //Überprüfung ob Signatur in Ordnung ist:
      bool istEntschluesselungErfolgreich;
      bool istSignaturValide;
      bool istSigniertesXmlValide;

      string xmlAsString = FiveRxSecurityResponse.VerifiziereRzeAntwort(serverAntwort,
                                                                        clientkeyStore,
                                                                        clientPasswort,
                                                                        out istEntschluesselungErfolgreich,
                                                                        out istSignaturValide,
                                                                        out istSigniertesXmlValide);



    }


  }
}
