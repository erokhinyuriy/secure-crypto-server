namespace SecureCryptoServer.Entities;

// НОВАЯ СУЩНОСТЬ ДЛЯ ОФФЛАЙН-ОЧЕРЕДИ
public class OfflineMessage
{
    public int Id { get; set; }
    public string Recipient { get; set; } = ""; // Кому доставить (в нижнем регистре)
    public string RawJsonPacket { get; set; } = ""; // Весь подписанный JSON-пакет целиком
}
