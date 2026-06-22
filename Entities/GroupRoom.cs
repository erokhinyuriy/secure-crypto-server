namespace SecureCryptoServer.Entities;

public class GroupRoom
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string GroupName { get; set; } = "";
    public string Creator { get; set; } = "";

    // Список участников группы (хранится в базе как строка через запятую "alice,bob,charlie")
    public string MembersRaw { get; set; } = "";

    public List<string> GetMembersList() =>
        new(MembersRaw.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
}
