using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using FiveRxLinkSecurityLib.Global;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace FiveRxLinkSecurityLib.Security
{
  public class CertHelper
  {

    /// <summary>
    /// Erstellt ein ein asymmetrisches Schlüsselpaar, ein Passwort für den privaten Teil des Zertifikates und generiert
    /// aus diesen erstellten Bestandteilen ein Zertifikat entsprechend der übergebenen Schlüsselstärke. Nach Bedarf können die 
    /// Bestandteile (Zertifikat, KeyStore, Passwort) auf dem Dateisystem gespeichert werden
    /// </summary>
    /// <param name="hashtype">Algorithmus des Hashtyps</param>
    /// <param name="antragsteller">Antragssteller (Subject DN)</param>
    /// <param name="aussteller">Austeller (Issuer DN)</param>
    /// <param name="passwortKeyStore">Passwort für den KeyStore, ist es leer wird eins geniert, ist es nicht leer wird das übertragene verwendet</param>
    /// <param name="keyStore">Rückgabe des generierten KeyStores als Objekt</param>
    /// <param name="gueltigVon">Ab wann ist das Zertifikat gültig</param>
    /// <param name="gueltiBis">Bis wann ist das Zertifikat gültig</param>
    /// <param name="keyStrength">Schlüsselstärke</param>
    /// <param name="zertifikatSpeicherPfad">Soll das Zertifikat auf einem Laufwerk gespeichert werden, wird hier der Ordner angegeben</param>
    /// <param name="dateiname">Namen der Dateien für das Passwort, das öffentliche Zertifikat und den KeyStore</param>
    /// <param name="zertifikatImPfadSpeichern">Soll das Zertifikat in dem angegebenen Pfad gespeichert werden (.der)</param>   
    /// <param name="keyStoreImPfadSpeicher">Soll der KeyStore in dem angebeneen Pfad gespeichert werden (.pfx)</param>
    /// <param name="passwortImPfadSpeichern">Soll das Passwort in dem angegebenen Pfad gespeichert werden (.pas)</param>
    /// <returns></returns>
    public static X509Certificate CreateCertificateAndKeyStore(Standards.HashType hashtype,
                                                               string antragsteller,
                                                               string aussteller,
                                                               ref string passwortKeyStore,
                                                               out Pkcs12Store keyStore,
                                                               DateTime gueltigVon,
                                                               DateTime gueltiBis,
                                                               KeyHelper.KeyStrength keyStrength = KeyHelper.KeyStrength.ks2048,
                                                               string zertifikatSpeicherPfad = null,
                                                               string dateiname = null,
                                                               bool zertifikatImPfadSpeichern = false,
                                                               bool keyStoreImPfadSpeicher = false,
                                                               bool passwortImPfadSpeichern = false)
    {
      //Erstellen eines Schlüsselpaares:
      AsymmetricCipherKeyPair schluesselPaar = KeyHelper.CreateAsymmetricKeyPair(keyStrength);

      //Erstellen eines Passwortes für den privaten Teil des Zertifikates:
      if (string.IsNullOrEmpty(passwortKeyStore))
      {
        passwortKeyStore = KeyHelper.CreateRSAPasswort();
      }

      //Erstellen des Zertifikates:
      X509Certificate certificate = CreateX509Certificate(schluesselPaar.Public, schluesselPaar.Private, hashtype, antragsteller, aussteller, gueltigVon, gueltiBis);

      //Erstelle KeyStore:
      keyStore = CreatePkcs12Store(certificate, schluesselPaar, antragsteller);

      //Falls ein Pfad angegeben ist und das Speichern der Zertifikatsinformationen gewünscht ist, werden diese
      //im Pfad als PKcs12 und DER Format gespeichert, das Passwort falls gewünscht in einer Textfile
      if (!string.IsNullOrEmpty(zertifikatSpeicherPfad))
      {
        if (string.IsNullOrEmpty(dateiname))
        {
          dateiname = aussteller + "_" + antragsteller + "_" + DateTime.Now.ToString("yyyyMMddHHmmss");
        }

        string speicherPfad = zertifikatSpeicherPfad + "\\" + dateiname;

        //Speichern des Zertifikates
        if (zertifikatImPfadSpeichern)
        {
          SaveCertAsDER(certificate, speicherPfad);
        }

        //Speichern des KeyStores
        if (keyStoreImPfadSpeicher)
        {
          SaveCertAsPkcs12(keyStore, speicherPfad, passwortKeyStore);
        }

        //Speichern des Passwortes:
        if (passwortImPfadSpeichern)
        {
          ParseHelper.WriteTextToFile(speicherPfad + ".pas", passwortKeyStore);
        }
      }

      return certificate;
    }



    /// <summary>
    /// Erstellt ein ein asymmetrisches Schlüsselpaar, ein Passwort für den privaten Teil des Zertifikates und generiert
    /// aus diesen erstellten Bestandteilen ein Zertifikat entsprechend der übergebenen Schlüsselstärke. Nach Bedarf können die 
    /// Bestandteile (Zertifikat, KeyStore, Passwort) auf dem Dateisystem gespeichert werden
    /// </summary>
    /// <param name="hashtype">Algorithmus des Hashtyps</param>
    /// <param name="antragsteller">Antragssteller (Subject DN)</param>
    /// <param name="aussteller">Austeller (Issuer DN)</param>
    /// <param name="passwortKeyStore">Passwort für den KeyStore, ist es leer wird eins geniert, ist es nicht leer wird das übertragene verwendet</param>
    /// <param name="keyStore">Rückgabe des generierten KeyStores als Objekt</param>
    /// <param name="gueltigVon">Ab wann ist das Zertifikat gültig</param>
    /// <param name="gueltiBis">Bis wann ist das Zertifikat gültig</param>
    /// <param name="keyStrength">Schlüsselstärke</param>
    /// <param name="zertifikatSpeicherPfad">Soll das Zertifikat auf einem Laufwerk gespeichert werden, wird hier der Ordner angegeben</param>
    /// <param name="dateiname">Namen der Dateien für das Passwort, das öffentliche Zertifikat und den KeyStore</param>
    /// <param name="zertifikatImPfadSpeichern">Soll das Zertifikat in dem angegebenen Pfad gespeichert werden (.der)</param>   
    /// <param name="keyStoreImPfadSpeicher">Soll der KeyStore in dem angebeneen Pfad gespeichert werden (.pfx)</param>
    /// <param name="passwortImPfadSpeichern">Soll das Passwort in dem angegebenen Pfad gespeichert werden (.pas)</param>
    /// <param name="caCertificate">Stammzertifikat</param>
    /// <returns></returns>
    public static X509Certificate CreateClientCertificateAndKeyStore(Pkcs12Store caStore,
                                                                     X509Certificate caCertificate,
                                                                     Standards.HashType hashtype,
                                                                     string antragsteller,
                                                                     string aussteller,
                                                                     ref string passwortKeyStore,
                                                                     out Pkcs12Store keyStore,
                                                                     DateTime gueltigVon,
                                                                     DateTime gueltiBis,
                                                                     KeyHelper.KeyStrength keyStrength = KeyHelper.KeyStrength.ks2048,
                                                                     string zertifikatSpeicherPfad = null,
                                                                     string dateiname = null,
                                                                     bool zertifikatImPfadSpeichern = false,
                                                                     bool keyStoreImPfadSpeicher = false,
                                                                     bool passwortImPfadSpeichern = false)
    {
      //Erstellen eines Schlüsselpaares:
      AsymmetricCipherKeyPair schluesselPaar = KeyHelper.CreateAsymmetricKeyPair(keyStrength);

      //Erstellen eines Passwortes für den privaten Teil des Zertifikates:
      if (string.IsNullOrEmpty(passwortKeyStore))
      {
        passwortKeyStore = KeyHelper.CreateRSAPasswort();
      }

      AsymmetricKeyParameter caPrivateKey = KeyHelper.GetPrivateKeyFromPkcs12Store(caStore);

      //Erstellen des Zertifikates:
      X509Certificate certificate = CreateX509Certificate(schluesselPaar.Public,
                                                          schluesselPaar.Private,
                                                          hashtype, antragsteller,
                                                          aussteller,
                                                          gueltigVon,
                                                          gueltiBis,
                                                          caCertificate,
                                                          caPrivateKey);

      //Erstelle KeyStore:
      keyStore = CreatePkcs12Store(certificate, schluesselPaar, antragsteller, caCertificate);

      //Falls ein Pfad angegeben ist und das Speichern der Zertifikatsinformationen gewünscht ist, werden diese
      //im Pfad als PKcs12 und DER Format gespeichert, das Passwort falls gewünscht in einer Textfile
      if (!string.IsNullOrEmpty(zertifikatSpeicherPfad))
      {
        if (string.IsNullOrEmpty(dateiname))
        {
          dateiname = aussteller + "_" + antragsteller + "_" + DateTime.Now.ToString("yyyyMMddHHmmss");
        }

        string speicherPfad = zertifikatSpeicherPfad + "\\" + dateiname;

        //Speichern des Zertifikates
        if (zertifikatImPfadSpeichern)
        {
          SaveCertAsDER(certificate, speicherPfad);
        }

        //Speichern des KeyStores
        if (keyStoreImPfadSpeicher)
        {
          SaveCertAsPkcs12(keyStore, speicherPfad, passwortKeyStore);
        }

        //Speichern des Passwortes:
        if (passwortImPfadSpeichern)
        {
          ParseHelper.WriteTextToFile(speicherPfad + ".pas", passwortKeyStore);
        }
      }

      return certificate;
    }

    /// <summary>
    /// Speichert den PKCS KeyStores in eine Datei ab
    /// </summary>
    /// <param name="pkcsStore">KeyStore</param>
    /// <param name="pfad">Pfad mit Dateinamen</param>
    /// <param name="keyStorePasswort">Passwort für den KeyStore</param>
    public static void SaveCertAsPkcs12(Pkcs12Store pkcsStore, string pfad, string keyStorePasswort)
    {
      if (!pfad.EndsWith(".pfx"))
      {
        pfad += ".pfx";
      }

      using (FileStream filestream = new FileStream(pfad, FileMode.Create, FileAccess.ReadWrite))
      {
        pkcsStore.Save(filestream, keyStorePasswort.ToCharArray(), new SecureRandom());
      }
    }

    /// <summary>
    /// Speichert das X509 Zertifikat im öffentlichen DER Format
    /// </summary>
    /// <param name="certificate">Zertifikat</param>
    /// <param name="pfad">Pfad mit Dateinamen</param>
    public static void SaveCertAsDER(X509Certificate certificate, string pfad)
    {
      if (!pfad.EndsWith(".der"))
      {
        pfad += ".der";
      }

      byte[] encodedCert = certificate.GetEncoded();

      using (FileStream outStream = new FileStream(pfad, FileMode.Create, FileAccess.ReadWrite))
      {
        outStream.Write(encodedCert, 0, encodedCert.Length);
      }
    }

    /// <summary>
    /// Generiert zu den übergebenen Parametern ein X509 Zertifikat.
    /// </summary>
    /// <param name="keyPair">Asymmetrisches Schlüsselpaar</param>
    /// <param name="hashtype">Verschlüsselungsalgorithmus</param>
    /// <param name="antragssteller">Antragssteller</param>
    /// <param name="aussteller">Aussteller</param>
    /// <param name="gueltigVon">Ab wann ist das Zertifikat gültig</param>
    /// <param name="gueltigBis">Bis wann ist das Zertifikat gültig</param>
    /// <param name="caZertifikat">Stammzertifikat</param>
    /// <param name="caPrivateKey">Privater Schlüssel Stammzertifikat</param>
    /// <returns></returns>
    private static X509Certificate CreateX509Certificate(AsymmetricKeyParameter oeffentlicherSchluessel,
                                                         AsymmetricKeyParameter privaterSchluessel,
                                                         Standards.HashType hashtype,
                                                         string antragssteller,
                                                         string aussteller,
                                                         DateTime? gueltigVon = null,
                                                         DateTime? gueltigBis = null,
                                                         X509Certificate caZertifikat = null,
                                                         AsymmetricKeyParameter caPrivateKey = null
                                                         )
    {
      if (!gueltigVon.HasValue)
      {
        gueltigVon = DateTime.Parse(DateTime.Now.ToString("dd.MM.yyyy 00:00:00"));
      }
      else
      {
        gueltigVon = DateTime.Parse(gueltigVon.Value.ToString("dd.MM.yyyy"));
      }

      if (!gueltigBis.HasValue)
      {
        gueltigBis = DateTime.Now.AddYears(1);
      }
      else
      {
        gueltigBis = DateTime.Parse(gueltigBis.Value.ToString("dd.MM.yyyy"));
      }

      X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

      ArrayList nameOidsSubjectDn = new ArrayList();
      nameOidsSubjectDn.Add(X509Name.CN);
      nameOidsSubjectDn.Add(X509Name.O);
      nameOidsSubjectDn.Add(X509Name.C);

      ArrayList nameValuesSubjectDn = new ArrayList();
      nameValuesSubjectDn.Add(antragssteller);
      nameValuesSubjectDn.Add(antragssteller);
      nameValuesSubjectDn.Add("DE");
      X509Name subjectDN = new X509Name(nameOidsSubjectDn, nameValuesSubjectDn);

      certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
      certGenerator.SetNotBefore(gueltigVon.Value);
      certGenerator.SetNotAfter(gueltigBis.Value);
      certGenerator.SetSubjectDN(subjectDN);
      certGenerator.SetPublicKey(oeffentlicherSchluessel);
      certGenerator.SetSignatureAlgorithm(hashtype.ToString());


      X509Certificate certificate = null;

      if (caZertifikat != null)
      {
        certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caZertifikat.GetPublicKey()));
        certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(oeffentlicherSchluessel));
        certGenerator.SetIssuerDN(caZertifikat.IssuerDN);
        certificate = certGenerator.Generate(caPrivateKey);
      }
      else
      {
        ArrayList nameOidsIssuerDn = new ArrayList();
        nameOidsIssuerDn.Add(X509Name.CN);
        nameOidsIssuerDn.Add(X509Name.O);
        nameOidsIssuerDn.Add(X509Name.C);

        ArrayList nameValuesIssuerDn = new ArrayList();
        nameValuesIssuerDn.Add(antragssteller);
        nameValuesIssuerDn.Add(antragssteller);
        nameValuesIssuerDn.Add("DE");
        X509Name issuerDn = new X509Name(nameOidsSubjectDn, nameValuesIssuerDn);

        certGenerator.SetIssuerDN(issuerDn);

        certificate = certGenerator.Generate(privaterSchluessel);
      }

      return certificate;
    }

    /// <summary>
    /// Lädt ein selbst generiertes Zertifikat / Zertifikat in den lokalen Zertifikatsspeichers des Computerkontos in die Bereiche
    /// Vertrauenswürdige Personen, Vertrauenswürdige Stammzertifizierungstellen und Eigene Zertifikate
    /// </summary>
    /// <param name="certificate"></param>
    public static void LadeX509CaZertifikatInMaschinenStore(X509Certificate certificate, string passwort)
    {
      LadeX509InZertifikatsspeicher(certificate,
                                    passwort,
                                    System.Security.Cryptography.X509Certificates.StoreName.TrustedPeople,
                                    System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);

      LadeX509InZertifikatsspeicher(certificate,
                                    passwort,
                                    System.Security.Cryptography.X509Certificates.StoreName.AuthRoot,
                                    System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
    }


    /// <summary>
    /// Lädt ein selbt generiertes Zertifikat / Zertifikat in den 
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="passwort"></param>
    public static void LadeX509ClientZertifikatInEigenenZertifikatsspeicher(X509Certificate certificate, string passwort)
    {
      LadeX509InZertifikatsspeicher(certificate,
                                    passwort,
                                    System.Security.Cryptography.X509Certificates.StoreName.My,
                                    System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
    }

    /// <summary>
    /// Lädt ein Zertifikat in einen Zertifikatsspeicher
    /// </summary>
    /// <param name="certificate">Zertifikat</param>
    /// <param name="zertifikatziel">Bereich in dem Zertifikatsspeicher in dem das Zertifikat abgelegt werden soll</param>
    /// <param name="zertifikatspeicher">Zertifikatspeicher (Computerkonto, Benutzerkonto, Dienstkonto)</param>
    private static void LadeX509InZertifikatsspeicher(X509Certificate certificate,
                                                      string passwort,
                                                      System.Security.Cryptography.X509Certificates.StoreName zertifikatziel,
                                                      System.Security.Cryptography.X509Certificates.StoreLocation zertifikatspeicher)
    {


      System.Security.Cryptography.X509Certificates.X509Certificate2 tempCert =
            new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded(),
                                                                               passwort,
                                                                               System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet);

      System.Security.Cryptography.X509Certificates.X509Store store = new System.Security.Cryptography.X509Certificates.X509Store(zertifikatziel, zertifikatspeicher);
      store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
      store.Add(tempCert);
      store.Close();
    }

    /// <summary>
    /// Lädt ein Zertifikat aus dem lokalen Zertifikatsspeicher des Computerkontos. Gesucht wird in em Bereich eigene Zertifikate
    /// </summary>
    /// <param name="anzeigenname"></param>
    /// <returns></returns>
    public static X509Certificate LadeX509AusMaschinenStore(string antragsteller)
    {
      X509Certificate certificate = null;

      System.Security.Cryptography.X509Certificates.X509Store store =
        new System.Security.Cryptography.X509Certificates.X509Store(System.Security.Cryptography.X509Certificates.StoreName.TrustedPeople,
                                                                    System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);

      store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

      foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 cert in store.Certificates)
      {
        if (cert.Subject.Contains(antragsteller))
        {
          return DotNetUtilities.FromX509Certificate(cert);
        }
      }

      return certificate;
    }


    /// <summary>
    /// Liest aus einem KeyStore das im KeyStore gespeicherte Zertifikat aus
    /// </summary>
    /// <param name="keyStore">KeyStore im PKCS12 Format</param>
    /// <returns>X509 Zertifikat</returns>
    public static X509Certificate LadeX509CertificateFromPkcs12Store(Pkcs12Store keyStore)
    {
      X509Certificate certificate = null;

      string certificateAlias = null;

      foreach (var certAliasKeyStore in keyStore.Aliases)
      {
        certificateAlias = certAliasKeyStore.ToString();
        break;
      }

      if (certificateAlias != null)
      {
        X509CertificateEntry certEntry = keyStore.GetCertificate(certificateAlias);
        certificate = certEntry.Certificate;
      }

      return certificate;
    }

    /// <summary>
    /// Umwandlung eines Zertifikates in einen Base64String
    /// </summary>
    /// <param name="cert">Bouncy X509 Zertifikat</param>
    /// <returns>Zertifikat als Base64 codierter String </returns>
    public static string ConvertX509ToBase64String(X509Certificate certificate)
    {
      byte[] certByteArray = certificate.GetEncoded();
      return Convert.ToBase64String(certByteArray);
    }

    /// <summary>
    /// Umwandlung eines Zertifikates in ein ByteArray
    /// </summary>
    /// <param name="cert">Bouncy X509 Zertifikat</param>
    /// <returns>Zertifikat als byte Array</returns>
    public static byte[] ConvertX509ToByteArray(X509Certificate certificate)
    {
      return certificate.GetEncoded();
    }

    /// <summary>
    /// Konvertierung eines KeyStores in einen Base64String
    /// </summary>
    /// <param name="store">KeyStore im PKCS12 Format</param>
    /// <param name="passwort">Passwort des KeyStores</param>
    /// <returns></returns>
    public static string ConvertPkcs12ToBase64String(Pkcs12Store store, string passwort)
    {
      return Convert.ToBase64String(ConvertPkcs12ToByteArray(store, passwort));
    }

    /// <summary>
    /// Konvertierung eines Pkcs KeyStores in ein byteArray
    /// </summary>
    /// <param name="store">KeyStore</param>
    /// <param name="passwort">Passwort zum KeyStore</param>
    /// <returns></returns>
    public static byte[] ConvertPkcs12ToByteArray(Pkcs12Store store, string passwort)
    {
      using (MemoryStream pkcs12data = new MemoryStream())
      {
        store.Save(pkcs12data, passwort.ToCharArray(), new SecureRandom());
        return pkcs12data.ToArray();
      }
    }

    /// <summary>
    /// Konvertierung eines Pkcs12Stores im ByteArrayFormat in Pkcs12 Objekt
    /// </summary>
    /// <param name="pkcs12ByteArray"></param>
    /// <param name="passwort"></param>
    /// <returns></returns>
    public static Pkcs12Store ConvertByteArrayToPkcs12Store(byte[] pkcs12ByteArray, string passwort)
    {
      Pkcs12Store keyStore;
      using (Stream stream = new MemoryStream(pkcs12ByteArray))
      {
        keyStore = new Pkcs12Store(stream, passwort.ToCharArray());
      }
      return keyStore;
    }


    /// <summary>
    /// Konvertierung eines im base64 Format vorliegenden Zertifikates in ein BouncyCastle Zertifikats Objekt
    /// </summary>
    /// <param name="base64Cert">In Base64 String Format vorliegendes Zertifikat</param>
    /// <returns>Bouncy X509 Zertifikat</returns>
    public static X509Certificate ConvertBase64StringToX509Certificate(string base64Cert)
    {
      System.Security.Cryptography.X509Certificates.X509Certificate2 tempCert = new System.Security.Cryptography.X509Certificates.X509Certificate2();

      byte[] certAsArray = Convert.FromBase64String(base64Cert);
      tempCert.Import(certAsArray);

      return DotNetUtilities.FromX509Certificate(tempCert);
    }


    public static Pkcs12Store ConvertBase64StringToPKCSKeyStore(string base64Cert, string passwort)
    {
      Pkcs12Store keyStore = new Pkcs12Store();

      byte[] keyStoreAsArray = Convert.FromBase64String(base64Cert);
      keyStore = CreatePkcs12Store(keyStoreAsArray, passwort, "");

      return keyStore;
    }

    public static X509Certificate ConvertByteArrayToX509Certificate(byte[] certAsByteArray)
    {
      X509CertificateParser parser = new X509CertificateParser();
      return parser.ReadCertificate(certAsByteArray);
    }

    /// <summary>
    /// Erstellung eines PKCS KeyStores
    /// </summary>
    /// <param name="certificate">Zertifikat für welches der KeyStore erstellt werden soll</param>
    /// <param name="keyPair">Schlüsselpaar welches dem KeyStore unterliegt</param>
    /// <param name="antragsteller">Antragsteller des Zertifikates</param>
    /// <param name="caZertifikat">Stammzertifikat falls es sich um dieses Zertifikat um ein Clientzertifikat handeln soll</param>
    /// <returns></returns>
    public static Pkcs12Store CreatePkcs12Store(X509Certificate certificate, AsymmetricCipherKeyPair keyPair, string antragsteller, X509Certificate caZertifikat = null)
    {
      Pkcs12Store pkcsStore = new Pkcs12StoreBuilder().Build();

      X509CertificateEntry certEntry = new X509CertificateEntry(certificate);
      pkcsStore.SetCertificateEntry(antragsteller, certEntry);

      if (caZertifikat != null)
      {
        var chainCerts = new List<X509CertificateEntry>();

        Dictionary<string, Org.BouncyCastle.X509.X509Certificate> chain = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>();
        string caCn = caZertifikat.SubjectDN.GetValues(X509Name.CN)[0].ToString();
        chain.Add(caCn, caZertifikat);

        var additionalCertsAsBytes = new List<byte[]>();
        if (chain != null && chain.Count > 0)
        {
          foreach (var additionalCert in chain)
          {
            additionalCertsAsBytes.Add(additionalCert.Value.GetEncoded());
          }
        }

        if (chain != null && chain.Count > 0)
        {
          var addicionalCertsAsX09Chain = BuildCertificateChainBC(certificate.GetEncoded(), additionalCertsAsBytes);

          foreach (var addCertAsX09 in addicionalCertsAsX09Chain)
          {
            X509Certificate tmpCertificate = (X509Certificate)addCertAsX09;
            chainCerts.Add(new X509CertificateEntry(tmpCertificate));
          }
        }
      }

      AsymmetricKeyEntry keyEntry = new AsymmetricKeyEntry(keyPair.Private);
      pkcsStore.SetKeyEntry(antragsteller, keyEntry, new X509CertificateEntry[] { certEntry });

      return pkcsStore;
    }

    private static IList BuildCertificateChainBC(byte[] primary, IEnumerable<byte[]> additional)
    {
      X509CertificateParser parser = new X509CertificateParser();
      PkixCertPathBuilder builder = new PkixCertPathBuilder();

      List<X509Certificate> intermediateCerts = new List<X509Certificate>();
      HashSet rootCerts = new HashSet();

      foreach (byte[] cert in additional)
      {
        X509Certificate x509Cert = parser.ReadCertificate(cert);

        // Separate root and subordinate certificates
        if (x509Cert.IssuerDN.Equivalent(x509Cert.SubjectDN))
          rootCerts.Add(new TrustAnchor(x509Cert, null));
        else
          intermediateCerts.Add(x509Cert);
      }

      X509CertStoreSelector holder = new X509CertStoreSelector();
      holder.Certificate = parser.ReadCertificate(primary);

      intermediateCerts.Add(holder.Certificate);

      PkixBuilderParameters builderParams = new PkixBuilderParameters(rootCerts, holder);
      builderParams.IsRevocationEnabled = false;

      X509CollectionStoreParameters intermediateStoreParameters =
          new X509CollectionStoreParameters(intermediateCerts);

      builderParams.AddStore(X509StoreFactory.Create(
          "Certificate/Collection", intermediateStoreParameters));

      PkixCertPathBuilderResult result = builder.Build(builderParams);

      return result.CertPath.Certificates;
    }


    public static X509Certificate Ladex509Certificate(string path)
    {
      X509CertificateParser parser = new X509CertificateParser();
      X509Certificate certificateX509 = parser.ReadCertificate(ParseHelper.GetByteArrayFromFile(path));
      return certificateX509;
    }

    public static Pkcs12Store LadePkcsStore(string path, string password)
    {
      Pkcs12Store store = null;

      using (FileStream fileStream = File.Open(path, FileMode.Open))
      {
        store = new Pkcs12Store(fileStream, password.ToCharArray());
        fileStream.Close();
        fileStream.Dispose();
      }
      return store;
    }

    public static Pkcs12Store CreatePkcs12Store(byte[] pkcs12Array, string password, string anzeigename)
    {
      System.Security.Cryptography.X509Certificates.X509Certificate2 tmpCert =
              new System.Security.Cryptography.X509Certificates.X509Certificate2(pkcs12Array,
                                                                                 password,
                                                                                 System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);

      System.Security.Cryptography.RSACryptoServiceProvider privateProvider = (System.Security.Cryptography.RSACryptoServiceProvider)tmpCert.PrivateKey;

      X509Certificate cert = DotNetUtilities.FromX509Certificate(tmpCert);
      AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(privateProvider);

      return CreatePkcs12Store(cert, keyPair, anzeigename);
    }





    public static X509Certificate tmpCertificate { get; set; }
  }
}
