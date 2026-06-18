namespace SecureCryptoServer.Entities;

public class UserDevice
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string PublicKeyBase64 { get; set; } = "";
}
