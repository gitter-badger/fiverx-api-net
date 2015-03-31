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
    internal class XmlDsigEnveloping : BaseXmlDsig
    {
        private bool c14 { get; set; }

        internal XmlDsigEnveloping(bool c14)
        {
            this.c14 = c14;
        }

        internal override XmlDocument SignXml(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort, string signaturAlgorithmus)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
  new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(keyStore, keyStorePasswort), keyStorePasswort);

            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = cert.PrivateKey;

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data(cert);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            // the DataObject has to point to a XmlNodeList
            DataObject dataObject = new DataObject();
            dataObject.Id = "MyObjectID1";
            dataObject.Data =
               new CustomXmlNodeList(new[] { xmlDoc.DocumentElement });
            signedXml.AddObject(dataObject);

            // Add the reference to the SignedXml object.
            Reference reference = new Reference();
            reference.Uri = "#MyObjectID1";
            signedXml.AddReference(reference);

            // Create a reference to be signed.
            if (c14)
            {
                XmlDsigC14NTransform env = new XmlDsigC14NTransform();
                reference.AddTransform(env);
            }

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // create detached envelope 
            XmlDocument envelope = new XmlDocument();
            envelope.AppendChild(envelope.CreateElement("Envelope"));

            envelope.DocumentElement.AppendChild(
               envelope.ImportNode(xmlDigitalSignature, true));

            return envelope;
        }
    }

    internal class CustomXmlNodeList : XmlNodeList
    {
        XmlNode[] _elements;

        public CustomXmlNodeList(XmlNode[] elements)
        {
            if (elements == null)
                throw new ArgumentException();

            this._elements = elements;
        }

        public override int Count
        {
            get { return _elements.Count(); }
        }

        public override System.Collections.IEnumerator GetEnumerator()
        {
            return _elements.GetEnumerator();
        }

        public override XmlNode Item(int index)
        {
            return _elements[index];
        }
    }

}
