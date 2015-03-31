using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace FiverxLinkSecurityLib.Security.XmlInteropSigning
{
    internal class XmlDsigEnveloped : BaseXmlDsig
    {
        private bool c14 { get; set; }

        internal XmlDsigEnveloped(bool c14)
        {
            this.c14 = c14;
        }


        internal override XmlDocument SignXml(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort, string signaturAlgorithmus)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
  new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);

            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = cert.PrivateKey;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.            
            XmlDsigEnvelopedSignatureTransform env =
               new XmlDsigEnvelopedSignatureTransform(true);
            reference.AddTransform(env);

            if (c14)
            {
                XmlDsigC14NTransform c14t = new XmlDsigC14NTransform();
                reference.AddTransform(c14t);
            }

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data(cert);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            xmlDoc.DocumentElement.AppendChild(
                xmlDoc.ImportNode(xmlDigitalSignature, true));

            return xmlDoc;
        }
    }

}
