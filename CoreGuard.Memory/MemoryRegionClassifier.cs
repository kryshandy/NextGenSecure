using System.Buffers.Binary;

namespace CoreGuard.Memory;

/// <summary>Nature d'une région mémoire suspecte.</summary>
public enum MemoryFindingKind
{
    /// <summary>
    /// Image PE complète (en-têtes MZ + « PE\0\0 ») dans de la mémoire PRIVÉE exécutable : DLL chargée de façon
    /// réflective, process hollowing, injection de module. Le chargeur Windows place les vraies DLL dans des
    /// régions de type IMAGE adossées à un fichier ; aucun moteur JIT ne fabrique d'en-tête PE. Signal fort.
    /// </summary>
    PeInPrivateMemory,

    /// <summary>
    /// Région privée lisible, inscriptible ET exécutable (RWX), sans en-tête PE : typique d'un shellcode, mais
    /// aussi des compilateurs à la volée (Java, navigateurs…). Signal faible : alerte seulement.
    /// </summary>
    PrivateRwx
}

/// <summary>Description d'une région (sous-ensemble de MEMORY_BASIC_INFORMATION).</summary>
public readonly record struct RegionInfo(ulong BaseAddress, ulong Size, uint State, uint Type, uint Protect);

/// <summary>Constat sur une région.</summary>
public sealed record MemoryFinding(MemoryFindingKind Kind, ulong BaseAddress, ulong Size, uint Protect);

/// <summary>Logique de classement des régions (pure : testable sans processus).</summary>
public static class MemoryRegionClassifier
{
    public const uint MemCommit = 0x1000;
    public const uint MemPrivate = 0x20000;
    public const uint MemImage = 0x1000000;
    public const uint MemMapped = 0x40000;

    public const uint PageExecute = 0x10, PageExecuteRead = 0x20, PageExecuteReadWrite = 0x40, PageExecuteWriteCopy = 0x80;
    public const uint PageGuard = 0x100, PageNoAccess = 0x01;

    public static bool IsExecutable(uint protect) =>
        (protect & (PageExecute | PageExecuteRead | PageExecuteReadWrite | PageExecuteWriteCopy)) != 0;

    /// <summary>Faut-il lire le début de cette région ? (mémoire privée, engagée, exécutable, lisible)</summary>
    public static bool IsCandidate(in RegionInfo r) =>
        r.State == MemCommit && r.Type == MemPrivate && IsExecutable(r.Protect)
        && (r.Protect & (PageGuard | PageNoAccess)) == 0 && r.Size >= 0x1000;

    /// <summary>Classe une région candidate à partir de ses premiers octets (au moins 0x400 conseillés).</summary>
    public static MemoryFinding? Classify(in RegionInfo r, ReadOnlySpan<byte> head)
    {
        if (!IsCandidate(r)) return null;
        if (LooksLikePe(head)) return new MemoryFinding(MemoryFindingKind.PeInPrivateMemory, r.BaseAddress, r.Size, r.Protect);
        if ((r.Protect & PageExecuteReadWrite) != 0) return new MemoryFinding(MemoryFindingKind.PrivateRwx, r.BaseAddress, r.Size, r.Protect);
        return null;
    }

    /// <summary>En-tête DOS « MZ » puis signature « PE\0\0 » à e_lfanew (borné, aligné) : vraie image PE.</summary>
    public static bool LooksLikePe(ReadOnlySpan<byte> head)
    {
        if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z') return false;
        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(head[0x3C..]);
        if (lfanew < 0x40 || lfanew > head.Length - 4 || (lfanew & 3) != 0) return false;
        return head[lfanew] == (byte)'P' && head[lfanew + 1] == (byte)'E' && head[lfanew + 2] == 0 && head[lfanew + 3] == 0;
    }
}
