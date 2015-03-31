using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Security.Cryptography.Xml;
using Org.BouncyCastle.Pkcs;

namespace FiverxLinkSecurityLib.Security.XmlInteropSigning
{
    internal abstract class BaseXmlDsig
    {
        internal abstract XmlDocument SignXml(XmlDocument xmlDoc, Pkcs12Store keyStore, string keyStorePasswort, string signaturAlgorithmus);

        internal bool VerifyXml(XmlDocument xmlDoc, out X509Certificate2 certificate)
        {
            certificate = null;

            byte[] stringData = Encoding.UTF8.GetBytes(xmlDoc.OuterXml);
            using (MemoryStream ms = new MemoryStream(stringData))
                return VerifyXmlFromStream(ms, out certificate);
        }

        internal bool VerifyXmlFromStream(System.IO.Stream SignedXmlDocumentStream, out X509Certificate2 certificate)
        {

            // load the document to be verified
            XmlDocument xd = new XmlDocument();
            xd.PreserveWhitespace = true;
            xd.Load(SignedXmlDocumentStream);

            SignedXml signedXml = new SignedXml(xd);

            // load the first <signature> node and load the signature  
            XmlNode MessageSignatureNode =
               xd.GetElementsByTagName("Signature")[0];

            signedXml.LoadXml((XmlElement)MessageSignatureNode);

            // get the cert from the signature
            certificate = null;
            foreach (KeyInfoClause clause in signedXml.KeyInfo)
            {
                if (clause is KeyInfoX509Data)
                {
                    if (((KeyInfoX509Data)clause).Certificates.Count > 0)
                    {
                        certificate =
                        (X509Certificate2)((KeyInfoX509Data)clause).Certificates[0];
                    }
                }
            }

            

            // check the signature and return the result.
            return signedXml.CheckSignature(certificate, true);
        }
    }

}
