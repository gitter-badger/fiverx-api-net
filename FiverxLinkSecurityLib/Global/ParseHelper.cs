using System;
using System.IO;
using System.Xml;

namespace FiveRxLinkSecurityLib.Global
{
  public class ParseHelper
  {

    public static byte[] GetByteArrayFromFile(string dateipfad)
    {
      byte[] certAsByteArray;

      using (FileStream fileStream = new FileStream(dateipfad, FileMode.Open, FileAccess.Read))
      {
        certAsByteArray = new byte[fileStream.Length];
        fileStream.Read(certAsByteArray, 0, (int)fileStream.Length);
        fileStream.Close();
        fileStream.Dispose();
      }

      return certAsByteArray;
    }

    public static string ReadTextFromFile(string dateipfad)
    {
      string text = "";

      using (StreamReader sr = new StreamReader(dateipfad, Standards.DefEncoding))
      {
        string zeile = "";

        while (zeile != null)
        {
          zeile = sr.ReadLine();

          if (!string.IsNullOrEmpty(text) && !string.IsNullOrEmpty(zeile))
          {
            text += Environment.NewLine;
          }

          text += zeile;
        }
      }

      return text;
    }

    public static void WriteTextToFile(string dateipfad, string text)
    {
      using (StreamWriter writer = new StreamWriter(dateipfad))
      {
        writer.Write(text);
        writer.Close();
      }
    }

    public static string ConvertXmlDocumentToString(XmlDocument xmldocument)
    {
      string xmlString = "";

      using (StringWriter stringWriter = new StringWriter())
      {
        using (XmlWriter xmlTextWriter = XmlWriter.Create(stringWriter))
        {
          xmldocument.WriteTo(xmlTextWriter);
          xmlTextWriter.Flush();
          xmlString = stringWriter.GetStringBuilder().ToString();
        }
      }

      return xmlString.Substring(xmlString.IndexOf(">") + 1, xmlString.Length - xmlString.IndexOf(">") - 1);
    }


  }
}
