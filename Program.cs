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
            var packet = JsonSerializer.Deserialize<SignedPacket>(jsonString, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
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

                // --- ВЫГРУЗКА ОФФЛАЙН СООБЩЕНИЙ ПРИ ВХОДЕ ---
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

                        db.OfflineMessages.RemoveRange(offlineMsgs);
                        await db.SaveChangesAsync();
                        Console.WriteLine($"[Очередь] Очередь для {authenticatedUser} успешно очищена.");
                    }
                }
            }

            if (packet.Type == "PING") continue;

            // --- МАРШРУТ А: ТЕКСТОВЫЕ СООБЩЕНИЯ ТЕТ-А-ТЕТ ---
            if (packet.Type == "MESSAGE" && !string.IsNullOrEmpty(packet.Recipient))
            {
                var recipient = packet.Recipient.ToLower().Trim();

                if (ActiveConnections.TryGetValue(recipient, out var recipientSocket) && recipientSocket.State == WebSocketState.Open)
                {
                    var forwardData = Encoding.UTF8.GetBytes(jsonString);
                    await recipientSocket.SendAsync(new ArraySegment<byte>(forwardData), WebSocketMessageType.Text, true, CancellationToken.None);
                    Console.WriteLine($"[Сеть] Сообщение от {authenticatedUser} переслано к {recipient} (Онлайн)");
                }
                else
                {
                    using (var scope = scopeFactory.CreateScope())
                    {
                        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
                        var offlineMessage = new OfflineMessage
                        {
                            Recipient = recipient,
                            RawJsonPacket = jsonString
                        };
                        db.OfflineMessages.Add(offlineMessage);
                        await db.SaveChangesAsync();
                        Console.WriteLine($"[Сейф] Получатель {recipient} оффлайн. Сообщение сохранено в очередь SQLite.");
                    }
                }
            }
            // --- МАРШРУТ В: МНОГОАДРЕСНОЕ ВЕЩАНИЕ ГРУППОВЫХ СООБЩЕНИЙ (ДОБАВЛЕНО) ---
            else if (packet.Type == "GROUP_MESSAGE" && !string.IsNullOrEmpty(packet.Recipient))
            {
                var groupNameTarget = packet.Recipient.Trim();
                var cleanGroupName = groupNameTarget.Replace("Группа:", "").Replace("группа:", "").Trim();

                using (var scope = scopeFactory.CreateScope())
                {
                    var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();

                    // Находим комнату в базе SQLite по её названию
                    var groupRoom = await db.Groups.FirstOrDefaultAsync(g => g.GroupName.ToLower() == cleanGroupName.ToLower());

                    if (groupRoom != null)
                    {
                        // Извлекаем список участников ("alice,bob,charlie")
                        var members = groupRoom.MembersRaw.Split(',', StringSplitOptions.RemoveEmptyEntries);

                        foreach (var member in members)
                        {
                            // Не пересылаем сообщение обратно автору, у него оно уже отрисовалось
                            if (member == senderName) continue;

                            // Если участник группы сейчас в сети — мгновенно кидаем ему пакет в сокет!
                            if (ActiveConnections.TryGetValue(member, out var memberSocket) && memberSocket.State == WebSocketState.Open)
                            {
                                var forwardData = Encoding.UTF8.GetBytes(jsonString);
                                await memberSocket.SendAsync(new ArraySegment<byte>(forwardData), WebSocketMessageType.Text, true, CancellationToken.None);
                            }
                            else
                            {
                                // Если кто-то оффлайн — бережно откладываем в оффлайн-очередь SQLite
                                var offlineMessage = new OfflineMessage
                                {
                                    Recipient = member,
                                    RawJsonPacket = jsonString
                                };
                                db.OfflineMessages.Add(offlineMessage);
                            }
                        }

                        await db.SaveChangesAsync();
                        Console.WriteLine($"[Сервер Групп] Групповое сообщение от {senderName} успешно размножено для участников чата '{cleanGroupName}'.");
                    }
                }
            }
            // --- МАРШРУТ Б: РАССЫЛКА КЛЮЧЕЙ ГРУППЫ (ИСПРАВЛЕНО) ---
            else if (packet.Type == "GROUP_KEY_DISTRIBUTION" && !string.IsNullOrEmpty(packet.Recipient))
            {
                var recipient = packet.Recipient.ToLower().Trim();

                // ИСПРАВЛЕНО: Используем правильный словарь ActiveConnections из вашей ОЗУ-структуры
                if (ActiveConnections.TryGetValue(recipient, out var recipientSocket) && recipientSocket.State == WebSocketState.Open)
                {
                    // Получатель в сети: пересылаем исходный крипто-пакет напрямую в его сокет
                    // ИСПРАВЛЕНО: Заменили json на jsonString
                    var forwardData = Encoding.UTF8.GetBytes(jsonString);
                    await recipientSocket.SendAsync(new ArraySegment<byte>(forwardData), WebSocketMessageType.Text, true, CancellationToken.None);
                    Console.WriteLine($"[Сеть Групп] Ключ группы от {authenticatedUser} успешно переслан к {recipient} (Онлайн)");
                }
                else
                {
                    // Получатель оффлайн: бережно складываем пакет ключей в общую очередь OfflineMessages
                    // ИСПРАВЛЕНО: Адаптировали под вашу структуру полей SQLite (Recipient + RawJsonPacket)
                    using (var scope = scopeFactory.CreateScope())
                    {
                        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
                        var offlineMessage = new OfflineMessage
                        {
                            Recipient = recipient,
                            RawJsonPacket = jsonString // Упаковываем весь JSON пакета с ключом целиком
                        };
                        db.OfflineMessages.Add(offlineMessage);
                        await db.SaveChangesAsync();
                        Console.WriteLine($"[Сейф Групп] Получатель {recipient} оффлайн. Ключ группы сохранен в очередь SQLite.");
                    }
                }
            }

        } // Конец цикла while
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[-] Ошибка WebSocket: {ex.Message}");
    }
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

#region Creation groups

// --- МАРШРУТ 1: СОЗДАНИЕ ГРУППЫ (Minimal API) ---
app.MapPost("/api/groups/create", async (GroupRoomDto dto, MessengerDbContext context) =>
{
    if (string.IsNullOrWhiteSpace(dto.GroupName) || dto.Members == null || dto.Members.Count == 0)
    {
        return Results.BadRequest("Некорректные данные группы");
    }

    // Принудительно добавляем создателя в список участников
    var membersList = dto.Members.Select(m => m.ToLower().Trim()).ToList();
    if (!membersList.Contains(dto.Creator.ToLower().Trim()))
    {
        membersList.Add(dto.Creator.ToLower().Trim());
    }

    var newGroup = new GroupRoom
    {
        GroupName = dto.GroupName,
        Creator = dto.Creator,
        MembersRaw = string.Join(",", membersList)
    };

    context.Groups.Add(newGroup);
    await context.SaveChangesAsync();

    return Results.Ok(new { GroupId = newGroup.Id, Message = "Группа зарегистрирована на сервере" });
});

// --- МАРШРУТ 2: ПОЛУЧЕНИЕ УЧАСТНИКОВ ГРУППЫ (Minimal API) ---
app.MapGet("/api/groups/{groupId:guid}/members", async (Guid groupId, MessengerDbContext context) =>
{
    var group = await context.Groups.FindAsync(groupId);
    if (group == null) return Results.NotFound("Группа не найдена");

    var membersList = group.MembersRaw.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
    return Results.Ok(membersList);
});

#endregion

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<SecureCryptoServer.Persistence.MessengerDbContext>();

    // ЖЕЛЕЗОБЕТОННЫЙ SQL-ХУК:
    // Мы шлем прямой, чистый запрос в SQLite. 
    // Инструкция "IF NOT EXISTS" гарантирует, что таблица создастся ТОЛЬКО если её нет,
    // и код НИКОГДА не вызовет ошибку "already exists", бережно сохраняя старых пользователей!
    string sql = @"
        CREATE TABLE IF NOT EXISTS ""Groups"" (
            ""Id"" TEXT NOT NULL PRIMARY KEY,
            ""GroupName"" TEXT NULL,
            ""Creator"" TEXT NULL,
            ""MembersRaw"" TEXT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ""IX_Groups_Id"" ON ""Groups"" (""Id"");
    ";

    // Выполняем команду напрямую в обход движка миграций
    dbContext.Database.ExecuteSqlRaw(sql);
}

app.Run();

// --- СЛУЖЕБНЫЕ МЕТОДЫ И DTO ---

// Математическая верификация подписи Ed25519
bool VerifyPacketSignature(SignedPacket packet, string publicKeyBase64)
{
    try
    {
        byte[] pubKeyBytes = Convert.FromBase64String(publicKeyBase64);
        byte[] sigBytes = Convert.FromBase64String(packet.Signature);

        // Приводим все строки к чистому, безопасному виду, страхуясь от null
        string cleanSender = (packet.Sender ?? "").ToLower().Trim();
        string cleanRecipient = (packet.Recipient ?? "").ToLower().Trim();
        string cleanType = packet.Type ?? "";
        string cleanPayload = packet.PayloadCipherBase64 ?? "";

        // ИСПРАВЛЕНО: Склеиваем строки в точно таком же формате, как на клиенте!
        // Никакие JSON-настройки больше физически не смогут сломать крипто-подпись Ed25519.
        string rawStringToVerify = $"{cleanSender}|{cleanRecipient}|{cleanType}|{cleanPayload}";
        byte[] messageBytes = Encoding.UTF8.GetBytes(rawStringToVerify);

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
