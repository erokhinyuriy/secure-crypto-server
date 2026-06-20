namespace SecureCryptoServer.Dtos;

// Обновляем структуру DTO регистрации на сервере
public record RegisterDto(
    string Username,
    string PublicKeyBase64,
    string EcdhIdentityKeyBase64,
    string SignedPrekeyBase64,
    string OneTimePrekeyBase64
);
