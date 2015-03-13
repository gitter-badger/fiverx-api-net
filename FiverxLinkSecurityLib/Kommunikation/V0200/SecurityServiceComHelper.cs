
using System;
using System.Net;
using System.ServiceModel;
using FiveRxLinkSecurityLib.Security;
using Org.BouncyCastle.Pkcs;
namespace FiverxLinkSecurityLib.Kommunikation.V0200
{
  public class SecurityServiceComHelper
  {
    public static FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient GetFiveRxServiceSecurityClient(string serviceAdresse,
                                                                                                           Pkcs12Store clientKeyStore,
                                                                                                           string clientKeyStorePasswort)
    {
      bool istSichereVerbindung = serviceAdresse.StartsWith("https");

      FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient client = new FiveRxSecurityService.FiveRxLinkSecurityServiceSoapClient();

      client.Endpoint.Address = new System.ServiceModel.EndpointAddress(new Uri(serviceAdresse));

      BasicHttpBinding binding = new BasicHttpBinding();
      binding.Security.Mode = istSichereVerbindung ? BasicHttpSecurityMode.Transport : BasicHttpSecurityMode.None;
      binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
      client.Endpoint.Binding = binding;

      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
        new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(clientKeyStore,
                                                                                                               clientKeyStorePasswort),
                                                                           clientKeyStorePasswort);

      client.ClientCredentials.ClientCertificate.Certificate = cert;

      if (istSichereVerbindung)
      {
        ServicePointManager.ServerCertificateValidationCallback =
               ((sender, certificate, chain, sslPolicyErrors) => true);
      }


      client.Open();

      return client;

    }
  }
}
