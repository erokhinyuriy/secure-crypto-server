namespace SecureCryptoServer.Dtos;

// Структура «Крипто-Паспорта» друга
public record PrekeyBundleDto(
    string Username,
    string Ed25519PublicKey,
    string EcdhIdentityKey,
    string SignedPrekey,
    string OneTimePrekey
);
