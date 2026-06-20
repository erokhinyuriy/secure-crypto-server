using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;
using SecureCryptoServer.Dtos;
using SecureCryptoServer.Entities;
using SecureCryptoServer.Persistence;

var builder = WebApplication.CreateBuilder(args);
Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

// Подключаем SQLite базу данных (файл базы будет лежать прямо в корне проекта)
builder.Services.AddDbContext<MessengerDbContext>(options =>
    options.UseSqlite("Data Source=server_identity.db"));

var app = builder.Build();

// Автоматическая инициализация базы данных при старте сервера
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
    db.Database.EnsureCreated();
}

app.UseWebSockets();

// Активные онлайн-подключения в ОЗУ: Имя пользователя -> Сокет
var ActiveConnections = new System.Collections.Concurrent.ConcurrentDictionary<string, WebSocket>();

// 1. HTTP API: Регистрация нового пользователя и его публичного ключа Ed25519
app.MapPost("/api/auth/register", async (RegisterDto request, MessengerDbContext db) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) ||
        string.IsNullOrWhiteSpace(request.PublicKeyBase64) ||
        string.IsNullOrWhiteSpace(request.EcdhIdentityKeyBase64) ||
        string.IsNullOrWhiteSpace(request.SignedPrekeyBase64) ||
        string.IsNullOrWhiteSpace(request.OneTimePrekeyBase64))
    {
        return Results.BadRequest("Неверные параметры. Переданы не все криптографические ключи.");
    }

    var normalizedUsername = request.Username.ToLower().Trim();

    var userExists = await db.Users.AnyAsync(u => u.Username == normalizedUsername);
    if (userExists)
        return Results.Conflict("Имя пользователя уже занято.");

    // Записываем устройство со всеми эллиптическими ключами в SQLite
    var newDevice = new UserDevice
    {
        Username = normalizedUsername,
        PublicKeyBase64 = request.PublicKeyBase64,
        EcdhIdentityKeyBase64 = request.EcdhIdentityKeyBase64,
        SignedPrekeyBase64 = request.SignedPrekeyBase64,
        OneTimePrekeyBase64 = request.OneTimePrekeyBase64
    };

    db.Users.Add(newDevice);
    await db.SaveChangesAsync();

    Console.WriteLine($"[X3DH] Успешно зарегистрирован профиль безопасности для: {normalizedUsername}");
    return Results.Ok(new { message = "Регистрация X3DH успешна." });
});

// 2. WEBSOCKET: Хост-фильтр для обмена сообщениями с проверкой Ed25519-подписи
app.Map("/ws", async (HttpContext context, IServiceScopeFactory scopeFactory) =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    using var webSocket = await context.WebSockets.AcceptWebSocketAsync();
    string? authenticatedUser = null;
    var buffer = new byte[1024 * 64];

    try
    {
        while (webSocket.State == WebSocketState.Open)
        {
            WebSocketReceiveResult result;
            try
            {
                result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
            }
            catch (WebSocketException)
            {
                Console.WriteLine($"[Сеть] Клиент {authenticatedUser ?? "Неизвестный"} отключился.");
                break;
            }

            if (result.MessageType == WebSocketMessageType.Close) break;

            var jsonString = Encoding.UTF8.GetString(buffer, 0, result.Count);
            var packet = JsonSerializer.Deserialize<SignedPacket>(jsonString);
            if (packet == null) continue;

            var senderName = packet.Sender.ToLower().Trim();

            using (var scope = scopeFactory.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
                var userDevice = await db.Users.FirstOrDefaultAsync(u => u.Username == senderName);

                if (userDevice == null || !VerifyPacketSignature(packet, userDevice.PublicKeyBase64))
                {
                    Console.WriteLine($"[⚠️ АТАКА] Крипто-подпись неверна для: {packet.Sender}");
                    break;
                }
            }

            // УСПЕШНАЯ АВТОРИЗАЦИЯ СЕССИИ
            if (authenticatedUser == null)
            {
                authenticatedUser = senderName;
                ActiveConnections[authenticatedUser] = webSocket;
                Console.WriteLine($"[+] Сессия успешно верифицирована для: {authenticatedUser}");

                // --- НОВАЯ ЛОГИКА: ВЫГРУЗКА ОФФЛАЙН СООБЩЕНИЙ ПРИ ВХОДЕ ---
                using (var scope = scopeFactory.CreateScope())
                {
                    var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
                    var offlineMsgs = await db.OfflineMessages
                        .Where(m => m.Recipient == authenticatedUser)
                        .ToListAsync();

                    if (offlineMsgs.Count > 0)
                    {
                        Console.WriteLine($"[Очередь] Найдено {offlineMsgs.Count} оффлайн-сообщений для {authenticatedUser}. Отправка...");

                        foreach (var offlineMsg in offlineMsgs)
                        {
                            var forwardData = Encoding.UTF8.GetBytes(offlineMsg.RawJsonPacket);
                            await webSocket.SendAsync(new ArraySegment<byte>(forwardData), WebSocketMessageType.Text, true, CancellationToken.None);
                        }

                        // После успешной отправки очищаем очередь в SQLite, чтобы не дублировать
                        db.OfflineMessages.RemoveRange(offlineMsgs);
                        await db.SaveChangesAsync();
                        Console.WriteLine($"[Очередь] Очередь для {authenticatedUser} успешно очищена.");
                    }
                }
                // --------------------------------------------------------
            }

            if (packet.Type == "PING") continue;

            if (packet.Type == "MESSAGE" && !string.IsNullOrEmpty(packet.Recipient))
            {
                var recipient = packet.Recipient.ToLower().Trim();

                if (ActiveConnections.TryGetValue(recipient, out var recipientSocket) && recipientSocket.State == WebSocketState.Open)
                {
                    // Получатель ОНЛАЙН: отправляем напрямую в сокет
                    var forwardData = Encoding.UTF8.GetBytes(jsonString);
                    await recipientSocket.SendAsync(new ArraySegment<byte>(forwardData), WebSocketMessageType.Text, true, CancellationToken.None);
                    Console.WriteLine($"[Сеть] Сообщение от {authenticatedUser} переслано к {recipient} (Онлайн)");
                }
                else
                {
                    // --- НОВАЯ ЛОГИКА: ПОЛУЧАТЕЛЬ ОФФЛАЙН -> СКЛАДЫВАЕМ В СЕЙФ СЕРВЕРА ---
                    using (var scope = scopeFactory.CreateScope())
                    {
                        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();

                        var offlineMessage = new OfflineMessage
                        {
                            Recipient = recipient,
                            RawJsonPacket = jsonString // Храним зашифрованный пакет в исходном виде
                        };

                        db.OfflineMessages.Add(offlineMessage);
                        await db.SaveChangesAsync();
                        Console.WriteLine($"[Сейф] Получатель {recipient} оффлайн. Сообщение сохранено в очередь SQLite.");
                    }
                    // --------------------------------------------------------------------
                }
            }
        }
    }
    catch (Exception ex) { Console.WriteLine($"[-] Ошибка WebSocket: {ex.Message}"); }
    finally
    {
        if (authenticatedUser != null) ActiveConnections.TryRemove(authenticatedUser, out _);
        if (webSocket.State == WebSocketState.Open || webSocket.State == WebSocketState.CloseReceived || webSocket.State == WebSocketState.CloseSent)
        {
            try { await webSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Closed", CancellationToken.None); } catch { }
        }
    }
});

// Эндпоинт для протокола X3DH: возвращает набор ключей собеседника для начала чата
app.MapGet("/api/crypto/prekey-bundle/{username}", async (string username, MessengerDbContext db) =>
{
    var targetUser = username.ToLower().Trim();
    var device = await db.Users.FirstOrDefaultAsync(u => u.Username == targetUser);

    if (device == null) return Results.NotFound("Пользователь не найден.");

    var bundle = new PrekeyBundleDto(
        device.Username,
        device.PublicKeyBase64,          // Ed25519 Identity
        device.EcdhIdentityKeyBase64,    // ECDH Identity
        device.SignedPrekeyBase64,       // ECDH Signed Prekey
        device.OneTimePrekeyBase64       // ECDH One-Time Prekey
    );

    // В настоящем Signal после выдачи OneTimePrekey он стирается из базы (одноразовый).
    // Для MVP оставим его постоянным, чтобы не усложнять логику пополнения ключей.

    return Results.Ok(bundle);
});

app.Run();

// --- СЛУЖЕБНЫЕ МЕТОДЫ И DTO ---

// Математическая верификация подписи Ed25519
bool VerifyPacketSignature(SignedPacket packet, string publicKeyBase64)
{
    try
    {
        byte[] pubKeyBytes = Convert.FromBase64String(publicKeyBase64);
        byte[] sigBytes = Convert.FromBase64String(packet.Signature);

        // ИСПРАВЛЕНО: Собираем строго стандартизированную строку данных для проверки
        // (Берем только Sender, Recipient, Type и Payload)
        var rawDataToVerify = new
        {
            s = packet.Sender.ToLower().Trim(),
            r = packet.Recipient.ToLower().Trim(),
            t = packet.Type,
            p = packet.PayloadCipherBase64
        };

        // Переводим в чистый JSON-текст без пробелов (стандарт .NET)
        string jsonToVerify = System.Text.Json.JsonSerializer.Serialize(rawDataToVerify);
        byte[] messageBytes = Encoding.UTF8.GetBytes(jsonToVerify);

        var algorithm = SignatureAlgorithm.Ed25519;
        var publicKey = PublicKey.Import(algorithm, pubKeyBytes, KeyBlobFormat.RawPublicKey);

        return algorithm.Verify(publicKey, messageBytes, sigBytes);
    }
    catch
    {
        return false;
    }
}

public class SignedPacket
{
    public string Sender { get; set; } = "";
    public string Recipient { get; set; } = "";
    public string Type { get; set; } = ""; // "PING" или "MESSAGE"
    public string PayloadCipherBase64 { get; set; } = ""; // Сквозное AES-GCM шифрование контента
    public string Signature { get; set; } = ""; // Подпись Ed25519, сгенерированная клиентом
}
