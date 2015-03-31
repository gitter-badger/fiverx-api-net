using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using FiverxLinkSecurityLib.Global;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using FiverxLinkSecurityLib.Security.XmlInteropSigning;
using Org.BouncyCastle.Security;

namespace FiverxLinkSecurityLib.Security
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

            SignXml(xmlDoc, signKeyStore, signkeyStorePasswort, konfiguration.XMLSigningAlgorithmus);

            XmlHelper.EncryptXML(xmlDoc,
                                 knotenZuVerschluesseln,
                                 konfiguration.XmlEncryptionNurInhaltDesZuVerschluesselndenKnotensVerschluesseln,
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
                                                         bool pruefeZertifikatAufRootZertifikatKompatibilitaet,
                                                         out bool istEntschluesselungErfolgreich,
                                                         out bool istSignaturValide,
                                                         out bool istRohdatenTransfer,
                                                         out string rawXmlData,
                                                         out X509Certificate signaturCertificate)
        {
            istEntschluesselungErfolgreich = false;
            istSignaturValide = false;
            istRohdatenTransfer = false;
            signaturCertificate = null;
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
            { }

            if (istEntschluesselungErfolgreich)
            {
                try
                {
                    XmlDocument doc = new XmlDocument();
                    doc.PreserveWhitespace = true;
                    doc.Load(@"C:\TempFiveRx\javaSigniertesXML.xml");

                    istSignaturValide = XmlHelper.VerifyXmlSignatureAndSignatureCertificate(tmpXml,
                                                                                            decryptionKeyStore,
                                                                                            decryptionKeyStorePasswort,
                                                                                            pruefeZertifikatAufRootZertifikatKompatibilitaet,
                                                                                            out signaturCertificate);
                }
                catch
                {

                }
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
        private static void SignXml(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort, string signaturAlgorithmus)
        {
            BaseXmlDsig xmlDsig = new XmlDsigEnveloped(true);
            xmlDoc = xmlDsig.SignXml(xmlDoc, keyStore, keyStorePasswort, signaturAlgorithmus);
        }

        /// <summary>
        /// Verifikation ob die Signatur des XML Dokumentes in Orndung ist und ob das Zertifikat mit welchem
        /// das XML Dokument siginiert wurde in seiner Zertifikatskette in Ordnung ist
        /// </summary>
        /// <param name="xmlDoc">signiertes XML Dokument</param>
        /// <param name="keyStore">KeyStore der zum Signierer gehört</param>
        /// <param name="keyStorePasswort">KeyStore Passwort</param>    
        /// <param name="xmlSignatureCertificate">Liefert das Zertifikat welches in der Signatur inkludiert ist</param>
        /// <returns>Ist Signatur ok und entspricht das mitgeteilte Zertifikat dem jenigen der das Zertikat gesendet hat</returns>
        private static bool VerifyXmlSignatureAndSignatureCertificate(XmlDocument xmlDoc,
                                                                      Pkcs12Store keyStore,
                                                                      string keyStorePasswort,
                                                                      bool verifiziereZertifikatRootAbstammung,
                                                                      out X509Certificate xmlSignatureCertificate)
        {
            xmlSignatureCertificate = null;
            System.Security.Cryptography.X509Certificates.X509Certificate2 signatureCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2();

            BaseXmlDsig xmlDsig = new XmlDsigEnveloped(true);
            bool signaturVerifiziert = xmlDsig.VerifyXml(xmlDoc, out signatureCertificate);

            //Erstellung eines Referenzzertifikates aus dem KeyStore:
            System.Security.Cryptography.X509Certificates.X509Certificate2 rootCert =
            new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);


            bool istZerifikatGefunden = false;

            xmlSignatureCertificate = DotNetUtilities.FromX509Certificate(signatureCertificate);

            if (verifiziereZertifikatRootAbstammung)
            {
                try
                {
                    xmlSignatureCertificate.Verify(CertHelper.LadeX509CertificateFromPkcs12Store(keyStore).GetPublicKey());
                    istZerifikatGefunden = true;
                }
                catch
                {
                    
                }
            }

            //Sollte die Zeritfikatherkunft (Abstammung von CA Zertifikat) verifiziert werden und stammt das Zertifikat nicht von
            //dem Root Zertifikat ab, dann wird als Prüfungsergebnis pauschal ein false zurückgegebn und somit die Signaturprüfung
            //als fehlgeschlagen markiert.
            if (verifiziereZertifikatRootAbstammung && !istZerifikatGefunden)
            {
                return false;
            }

            return signaturVerifiziert;
        }

        private static XmlNamespaceManager GetSoapNamespaces(XmlNameTable nameTable)
        {
            XmlNamespaceManager soapNamespaces = new XmlNamespaceManager(nameTable);

            soapNamespaces.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
            soapNamespaces.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            soapNamespaces.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            soapNamespaces.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            soapNamespaces.AddNamespace("addressing", "http://www.w3.org/2005/08/addressing");

            return soapNamespaces;
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
        /// <param name="aesAlgo">Algorithmus für die AES Verschlüsselung</param>
        /// <param name="useOAEP">Verwendung vom optimalen asymmetrischen Verschlüsselungs Padding</param>
        /// <param name="rsaAlgo">Algorithmus für die RSA Verschlüsselung</param>
        /// <param name="keyStore">KeyStore der für die Verschlüsselung herangezogen werden soll</param>
        /// <param name="keyStorePasswort">Passwort zum KeyStore</param>
        private static void EncryptXML(XmlDocument doc,
                                       string xmlElementToEncrypt,
                                       bool nurknotenInhaltVerschluesseln,
                                       string aesAlgo,
                                       bool useOAEP,
                                       string rsaAlgo,
                                       X509Certificate certEncryptInfo)
        {


            //Heranziehen des öffentlichen Schlüssels:
            RSACryptoServiceProvider publicKeyProvider = KeyHelper.ConvertAsymmetricKeyParameterToRSACryptoServiceProvider(certEncryptInfo.GetPublicKey());
            SymmetricAlgorithm aesAlgorithmus = SymmetricAlgorithm.Create(aesAlgo);

            //Definition des symmetrischen Verschlüsselungsverfahren:

            XmlElement elementToEncrypt = doc.GetElementsByTagName(xmlElementToEncrypt)[0] as XmlElement;
            RijndaelManaged sessionKey = new RijndaelManaged();

            sessionKey.KeySize = aesAlgorithmus.KeySize;

            //Asymmetrische Verschlüsselung des symmetrischen Schlüssels und der Daten:
            EncryptedXml eXml = new EncryptedXml();

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, nurknotenInhaltVerschluesseln);
            //byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, symalgorithmus, nurknotenInhaltVerschluesseln);

            //byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, publicKeyProvider, useOAEP);

            //TODO: useOAEP aus Algorithmus entnehmen!!!!!

            byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, publicKeyProvider, useOAEP);

            //Aufbereitung des verschlüsselten XMLs:
            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncNamespaceUrl;
            edElement.EncryptionMethod = new EncryptionMethod(/*GetEncryptionAlgorithmusValue(*/aesAlgo/*)*/);
            EncryptedKey ek = new EncryptedKey();
            ek.CipherData = new CipherData(encryptedKey);
            ek.EncryptionMethod = new EncryptionMethod(/*GetEncryptionAlgorithmusValue(*/rsaAlgo/*)*/);
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
