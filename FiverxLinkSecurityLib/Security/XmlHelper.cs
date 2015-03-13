using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using FiverxLinkSecurityLib.Security;
using FiveRxLinkSecurityLib.Global;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace FiveRxLinkSecurityLib.Security
{
  public class XmlHelper
  {
    /// <summary>
    /// Signatur und Verschlüsselung des XML
    /// </summary>
    /// <param name="xmlDoc"></param>
    /// <param name="signKeyStore"></param>
    /// <param name="signkeyStorePasswort"></param>
    /// <param name="knotenZuVerschluesseln"></param>
    /// <param name="konfiguration"></param>
    /// <param name="certForEncryption"></param>
    public static void SignAndEncryptXml(XmlDocument xmlDoc,
                                         Pkcs12Store signKeyStore,
                                         string signkeyStorePasswort,
                                         SecurityKonfiguration konfiguration,
                                         X509Certificate certForEncryption)
    {
      string knotenZuVerschluesseln = xmlDoc.DocumentElement.Name;

      SignXml(xmlDoc, signKeyStore, signkeyStorePasswort);

      XmlHelper.EncryptXML(xmlDoc,
                           knotenZuVerschluesseln,
                           konfiguration.XmlEncryptionNurInhaltDesZuVerschluesselndenKnotensVerschluesseln,
                           konfiguration.XmlEncryptionAesKeySize,
                           konfiguration.XmlEncryptionAesAlgorithmus,
                           konfiguration.XmlEncryptionUseOAEP,
                           konfiguration.XmlEncryptionRsaAlgorithmus,
                           certForEncryption);
    }

    /// <summary>
    /// Entschlüsselt die RzeAnfrage, verfiziert die Signatur und das Zerifikat mit dem die Signatur erstellt wurde.
    /// Zudem wird aus dem signierten XML das urprüngliche Rohdaten XML gewonnen
    /// </summary>
    /// <param name="encryptedData">Verschlüsselte Daten</param>
    /// <param name="decryptionKeyStore">KeyStore für die Entschlüsselung</param>
    /// <param name="decryptionKeyStorePasswort">Passwort für den KeyStore zur Entschlüsselung</param>
    /// <param name="signKeyStore">KeyStore welcher für die Signatur herangezogen wurde</param>
    /// <param name="signKeyStorePasswort">Passwort zum KeyStore der für die Sigantur heranzogen wurde</param>
    /// <param name="istEntschluesselungErfolgreich">Flag zur Kennzeichnung ob eine erfolgreiche Entschlüsselung stattgefunden hat</param>
    /// <param name="istSignaturValide">Flag zur Kennzeichnung ob die Signatur und das damit in Verbindugn stehende angegebene Zertifikat in Ordnung sind</param>
    /// <param name="istRohdatenTransfer">Flag ob das signierte XML in die Rohdaten überführt werden konnte</param>
    /// <param name="rawXmlData"></param>
    public static void DecryptVerifyXMLAndGetRawData(byte[] encryptedData,
                                                     Pkcs12Store decryptionKeyStore,
                                                     string decryptionKeyStorePasswort,
                                                     out bool istEntschluesselungErfolgreich,
                                                     out bool istSignaturValide,
                                                     out bool istRohdatenTransfer,
                                                     out string rawXmlData)
    {
      istEntschluesselungErfolgreich = false;
      istSignaturValide = false;
      istRohdatenTransfer = false;
      rawXmlData = "";

      string xmlSignedEncrypted = Standards.DefEncoding.GetString(encryptedData);

      XmlDocument tmpXml = new XmlDocument();
      tmpXml.LoadXml(xmlSignedEncrypted);

      try
      {
        XmlHelper.DecryptXML(tmpXml, decryptionKeyStore, decryptionKeyStorePasswort);
        istEntschluesselungErfolgreich = true;
      }
      catch
      {
      }

      if (istEntschluesselungErfolgreich)
      {
        try
        {
          istSignaturValide = XmlHelper.VerifyXmlSignature(tmpXml, decryptionKeyStore, decryptionKeyStorePasswort);
          //istSignaturValide = XmlHelper.VerifyXmlSignature(tmpXml, signKeyStore, signKeyStorePasswort);
        }
        catch { }
      }

      if (istEntschluesselungErfolgreich && istSignaturValide)
      {
        try
        {
          rawXmlData = XmlHelper.GetRawXmlFromSignedXmlStructure(tmpXml);
          istRohdatenTransfer = true;
        }
        catch { }

      }


    }

    /// <summary>
    /// Signatur eines XML Dokuments mit Hilfe des KeyStores. Aus dem KeyStore wird das Zertifikat gezogen und als
    /// Information, unter Berücksichtigung welchen Zeritfikats das XML signiert wurde, angehängt.
    /// </summary>
    /// <param name="xmlDoc">Zu signierendes XML Dokument</param>
    /// <param name="keyStore">KeyStore der zur Signierung herangezogen werden soll</param>
    /// <param name="keyStorePassword">Passwort zum KeyStore</param>
    private static void SignXml(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort)
    {
      //Erstellung eines Zertifikatobjektes aus dem KeyStore:

      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
        new System.Security.Cryptography.X509Certificates.X509Certificate2(@"C:\TempFiveRx\TestDotNetClientZertifikat.pfx", "testc");
      //new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);

      //Xml Vorbereitung:
      xmlDoc.PreserveWhitespace = false;

      SignedXml signedXml = new SignedXml(xmlDoc);
      signedXml.SigningKey = cert.PrivateKey;

      //MetaInformationen zur Signatur
      Reference metaData = new Reference();
      string id = Guid.NewGuid().ToString();
      metaData.Uri = "";
      metaData.Id = id;
      xmlDoc.DocumentElement.SetAttribute("sigId", id);

      XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
      metaData.AddTransform(env);

      signedXml.AddReference(metaData);

      //Information mit welchem Zertifikat das XML signiert wurde:
      KeyInfo zertifikatInformation = new KeyInfo();
      zertifikatInformation.AddClause(new KeyInfoX509Data(cert));
      signedXml.KeyInfo = zertifikatInformation;

      //Berechnung der Signatur und Bindung der Informationen:
      signedXml.ComputeSignature();
      XmlElement xmlDigitalSignature = signedXml.GetXml();
      xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
      if (xmlDoc.FirstChild is XmlDeclaration)
      {
        xmlDoc.RemoveChild(xmlDoc.FirstChild);
      }
    }

    /// <summary>
    /// Verifikation ob die Signatur des XML Dokumentes in Orndung ist und ob das Zertifikat mit welchem
    /// das XML Dokument siginiert wurde mit dem zum Benutzer bekannnten Zertifikat übereinstimmt
    /// </summary>
    /// <param name="xmlDoc">signiertes XML Dokument</param>
    /// <param name="keyStore">KeyStore der zum Signierer gehört</param>
    /// <param name="keyStorePasswort">KeyStore Passwort</param>
    /// <returns>Ist Signatur ok und entspricht das mitgeteilte Zertifikat dem jenigen der das Zertikat gesendet hat</returns>
    private static bool VerifyXmlSignature(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort)
    {
      //Erstellung eines Referenzzertifikates aus dem KeyStore:
      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
        new System.Security.Cryptography.X509Certificates.X509Certificate2(@"C:\TempFiveRx\TestDotNetClientZertifikat.pfx", "testc");
      //new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);

      //Xml Vorbereitung:
      xmlDoc.PreserveWhitespace = false;

      SignedXml signedXml = new SignedXml(xmlDoc);
      XmlNodeList signatureNodeList = xmlDoc.GetElementsByTagName("Signature");
      signedXml.LoadXml((XmlElement)signatureNodeList[0]);

      //Prüfung auf Signatur und Zertifikat:
      //CheckSignatur(cert,true) => Prüft ob die Signatur in Ordnung ist
      //CheckSignatur(cert,false) => Prüft ob die Signatur in Ordnung ist und ob das Zertifikat ok ist, welches im XML mit übergeben wird
      //die funktioniert aber nur, wenn das Zertifikat im Zerifikatsspeicher unter Vertrauenswürdige Personen eingelagert ist
      return signedXml.CheckSignature(cert, true);
    }


    /// <summary>
    /// Wandelt eine signierten XML Struktur in das urspprüngliche XML um
    /// </summary>
    /// <param name="signedXmlDocument">signierte XML Strukur</param>
    /// <returns>ursprüngliche XML Struktur als String</returns>
    private static string GetRawXmlFromSignedXmlStructure(XmlDocument signedXmlDocument)
    {
      XmlNodeList nodeListSignature = signedXmlDocument.GetElementsByTagName("Signature");
      signedXmlDocument.DocumentElement.RemoveChild((XmlElement)nodeListSignature[0]);
      signedXmlDocument.DocumentElement.RemoveAttribute("sigId");
      return ParseHelper.ConvertXmlDocumentToString(signedXmlDocument);
    }


    private static string GetEncryptionAlgorithmusValue(string encryptionAlgorithmusName)
    {
      FieldInfo[] fielInfos;
      fielInfos = typeof(EncryptedXml).GetFields();

      EncryptedXml xmlEncrypted = new EncryptedXml();

      foreach (FieldInfo field in fielInfos)
      {
        if (field.Name.Equals(encryptionAlgorithmusName))
        {
          return field.GetValue(xmlEncrypted) as string;
        }
      }
      return "";
    }

    /// <summary>
    /// Verschlüsseung eines XML Dokumentes
    /// </summary>
    /// <param name="doc">zu verschlüsselndes XML Dokument</param>
    /// <param name="xmlElementToEncrypt">Knoten im XML Dokument der für die Verschlüsselung betrachtet werden soll</param>
    /// <param name="nurknotenInhaltVerschluesseln">Soll nur der Inhalt (true) oder auch der Knoten selbst verschlüsselt werden (false)</param>
    /// <param name="aesKeySize">Schlüsselstärke für die AES Verschlüsselung</param>
    /// <param name="aesAlgo">Algorithmus für die AES Verschlüsselung</param>
    /// <param name="useOAEP">Verwendung vom optimalen asymmetrischen Verschlüsselungs Padding</param>
    /// <param name="rsaAlgo">Algorithmus für die RSA Verschlüsselung</param>
    /// <param name="keyStore">KeyStore der für die Verschlüsselung herangezogen werden soll</param>
    /// <param name="keyStorePasswort">Passwort zum KeyStore</param>
    private static void EncryptXML(XmlDocument doc,
                                   string xmlElementToEncrypt,
                                   bool nurknotenInhaltVerschluesseln,
                                   int aesKeySize,
                                   string aesAlgo,
                                   bool useOAEP,
                                   string rsaAlgo,
                                   X509Certificate certEncryptInfo)
    {


      //Heranziehen des öffentlichen Schlüssels:
      RSACryptoServiceProvider publicKeyProvider = KeyHelper.ConvertAsymmetricKeyParameterToRSACryptoServiceProvider(certEncryptInfo.GetPublicKey());

      //Definition des symmetrischen Verschlüsselungsverfahren:
      XmlElement elementToEncrypt = doc.GetElementsByTagName(xmlElementToEncrypt)[0] as XmlElement;
      RijndaelManaged sessionKey = new RijndaelManaged();
      sessionKey.KeySize = aesKeySize;

      //Asymmetrische Verschlüsselung des symmetrischen Schlüssels und der Daten:
      EncryptedXml eXml = new EncryptedXml();
      byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, nurknotenInhaltVerschluesseln);
      byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, publicKeyProvider, useOAEP);

      //Aufbereitung des verschlüsselten XMLs:
      EncryptedData edElement = new EncryptedData();
      edElement.Type = EncryptedXml.XmlEncNamespaceUrl;
      edElement.EncryptionMethod = new EncryptionMethod(GetEncryptionAlgorithmusValue(aesAlgo));
      EncryptedKey ek = new EncryptedKey();
      ek.CipherData = new CipherData(encryptedKey);
      ek.EncryptionMethod = new EncryptionMethod(GetEncryptionAlgorithmusValue(rsaAlgo));
      edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

      //Zur Java Kompatibilität:
      KeyInfoName kin = new KeyInfoName();
      kin.Value = "rsaKeyName";
      ek.KeyInfo.AddClause(kin);
      edElement.CipherData.CipherValue = encryptedElement;

      EncryptedXml.ReplaceElement(elementToEncrypt, edElement, nurknotenInhaltVerschluesseln);
    }


    /// <summary>
    /// Entschlüsselung einer verschlüsselten XML Struktur
    /// </summary>
    /// <param name="Doc"></param>
    /// <param name="keyStore"></param>
    /// <param name="keyStorePasswort"></param>
    private static void DecryptXML(XmlDocument Doc, Pkcs12Store keyStore, string keyStorePasswort)
    {

      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
          new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);


      //Heranziehen des privaten Schlüssels:

      RSACryptoServiceProvider privateKeyProvider = null;

      privateKeyProvider = (RSACryptoServiceProvider)(cert.PrivateKey);


      //Kompatibilität Java Anfang -->

      XmlElement keyNameNode = null;
      string keyName = "rsaKeyName";

      foreach (string keyNameName in GetNodeKeyNameCollection())
      {
        keyNameNode = Doc.GetElementsByTagName(keyNameName)[0] as XmlElement;
        if (keyNameNode != null)
        {
          break;
        }
      }

      if (keyNameNode == null)
      {
        XmlElement encryptedKey = null;
        foreach (string encryptionKeyName in GetNodeEncryptionKeyNameCollection())
        {
          encryptedKey = Doc.GetElementsByTagName(encryptionKeyName)[0] as XmlElement;
          if (encryptedKey != null)
          {
            break;
          }
        }

        if (encryptedKey != null)
        {
          XmlElement elementKeyMethod = null;

          foreach (string elementKeyMethodName in GetNodeEncryptionMethodCollection())
          {
            elementKeyMethod = encryptedKey.GetElementsByTagName(elementKeyMethodName)[0] as XmlElement;
            if (elementKeyMethod != null)
            {
              break;
            }
          }

          if (elementKeyMethod != null)
          {
            XmlElement elementKeyInfo = Doc.CreateElement("KeyInfo", SignedXml.XmlDsigNamespaceUrl);
            XmlElement elementKeyName = Doc.CreateElement("KeyName", SignedXml.XmlDsigNamespaceUrl);
            elementKeyName.InnerText = keyName;
            elementKeyInfo.AppendChild(elementKeyName);
            encryptedKey.InsertAfter(elementKeyInfo, elementKeyMethod);
          }

        }
      }
      else
      {
        if (!string.IsNullOrEmpty(keyNameNode.InnerText))
        {
          keyName = keyNameNode.InnerText;
        }
        else
        {
          keyName = "";
        }
      }
      // Kompatibilität Java Ende <--

      //Entschlüsselung:
      EncryptedXml exml = new EncryptedXml(Doc);
      exml.AddKeyNameMapping(keyName, privateKeyProvider);
      exml.DecryptDocument();

    }

    private static List<string> GetNodeEncryptionKeyNameCollection()
    {
      List<string> encryptionKeys = new List<string>();
      encryptionKeys.Add("EncryptedKey");
      encryptionKeys.Add("xenc:EncryptedKey");
      return encryptionKeys;
    }

    private static List<string> GetNodeKeyNameCollection()
    {
      List<string> keyNames = new List<string>();
      keyNames.Add("KeyName");
      keyNames.Add("xenc:KeyName");
      return keyNames;
    }

    private static List<string> GetNodeEncryptionMethodCollection()
    {
      List<string> encryptionMethods = new List<string>();
      encryptionMethods.Add("EncryptionMethod");
      encryptionMethods.Add("xenc:EncryptionMethod");
      return encryptionMethods;
    }

    public static void SaveXmlDocumentToFile(string pfadXmlDocument, XmlDocument doc)
    {
      using (TextWriter sw = new StreamWriter(pfadXmlDocument, false, Standards.DefEncoding))
      {
        doc.Save(sw);
      }
    }
  }
}
