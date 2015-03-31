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
    internal class XmlDsigDetached : BaseXmlDsig
    {
        private bool c14 { get; set; }

        internal XmlDsigDetached(bool c14)
        {
            this.c14 = c14;
        }

   

        internal override XmlDocument SignXml(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort, string signaturAlgorithmus)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
  new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);

            // create detached envelope 
            XmlDocument envelope = new XmlDocument();
            envelope.PreserveWhitespace = true;
            envelope.AppendChild(envelope.CreateElement("Envelope"));

            XmlElement message = envelope.CreateElement("Message");
            message.InnerXml = xmlDoc.DocumentElement.OuterXml;
            message.SetAttribute("Id", "MyObjectID");
            envelope.DocumentElement.AppendChild(message);

            SignedXml signedXml = new SignedXml(envelope);
            signedXml.SigningKey = cert.PrivateKey;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "#MyObjectID";

            if (c14)
            {
                XmlDsigC14NTransform env = new XmlDsigC14NTransform();
                reference.AddTransform(env);
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

            envelope.DocumentElement.AppendChild(
               envelope.ImportNode(xmlDigitalSignature, true));

            return envelope;
        }

    }

}
