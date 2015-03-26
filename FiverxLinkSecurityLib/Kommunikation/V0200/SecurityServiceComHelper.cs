
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using FiverxLinkSecurityLib.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
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
      binding.UseDefaultWebProxy = true;
      client.Endpoint.Binding = binding;

      //X509Certificate cert2 = CertHelper.LadeX509CertificateFromPkcs12Store(clientKeyStore);
      
      /*
      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
        new System.Security.Cryptography.X509Certificates.X509Certificate2(@"C:\TempFiveRx\TestDotNetClientZertifikat.der");
      */
      /*
      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
        new System.Security.Cryptography.X509Certificates.X509Certificate2(CertHelper.ConvertPkcs12ToByteArray(clientKeyStore,clientKeyStorePasswort),clientKeyStorePasswort);
      */
      System.Security.Cryptography.X509Certificates.X509Certificate2 cert =
        new System.Security.Cryptography.X509Certificates.X509Certificate2(@"C:\TempFiveRx\TestDotNetClientZertifikat.pfx",clientKeyStorePasswort);



      client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindByThumbprint, "02 4b 4d 05 63 53 d1 7f 92 d1 5f 74 df fb 24 6e a2 8e 0f d9"); 


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
