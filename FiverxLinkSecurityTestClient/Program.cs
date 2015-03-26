


using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
namespace FiverxLinkSecurityTestClient
{
  class Program
  {
    static void Main(string[] args)
    {
      Demolauf();
    }

    private static void Demolauf()
    {
      Demo.testx();

      //Demo.DemoServerZertifikat(true);
      //Demo.DemoClientZertifikat();
      Demo.DemoRzeAnfrage();
      //Demo.DemoRzeAntwort();
      //Demo.DemoServiceAnfrageVerarbeiteAuftrag();
      //Demo.DemoServiceAnfrageLadeSicherheitsmerkmale();
      //Demo.DemoServiceAnfrageLadeRzSecurityVersion();
    }

    
  }
}
