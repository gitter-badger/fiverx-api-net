using Org.BouncyCastle.OpenSsl;

namespace FiverxLinkSecurityLib.BouncyCastle
{
  public class Password : IPasswordFinder
  {
    private string _password { get; set; }

    public Password(string password)
    {
      _password = password;
    }

    public char[] GetPassword()
    {
      return _password.ToCharArray();
    }
  }
}
