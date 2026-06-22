namespace SecureCryptoServer.Entities;

public class UserDevice
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string PublicKeyBase64 { get; set; } = "";

    // --- НОВЫЕ ПОЛЯ ДЛЯ X3DH ---
    // Постоянный ECDH ключ для шифрования (Identity Key)
    public string EcdhIdentityKeyBase64 { get; set; } = "";

    // Временный подписанный ECDH ключ (Signed Prekey)
    public string SignedPrekeyBase64 { get; set; } = "";

    // НОВОЕ ПОЛЕ: подпись Ed25519 над SignedPrekeyBase64, сделанная Identity-ключом клиента.
    // Без неё получатель бандла не может убедиться, что SignedPrekey не подменён сервером.
    public string SignedPrekeySignatureBase64 { get; set; } = "";

    // Одноразовый ECDH ключ (One-Time Prekey)
    public string OneTimePrekeyBase64 { get; set; } = "";
}
