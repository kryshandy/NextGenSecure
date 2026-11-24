using System.Reflection.PortableExecutable;
using System.Text;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

// Analyse statique d'un fichier PE (exe, dll, sys...) sans l'exécuter.
// Tout le contenu du fichier est traité comme une donnée non fiable : on ne reprend
// jamais dans les descriptions que des noms issus de listes internes ou assainis.
public sealed class PeStaticEngine : IDetectionEngine
{
    private const double SeuilEntropieSection = 7.2;
    private const int TailleMiniSection = 2048;
    private const int TailleMaxLectureSection = 64 * 1024 * 1024;
    private const int MaxImports = 20000;
    private const int MaxDll = 512;
    private const int PointsMaxImports = 35;

    // Imports sensibles (API fréquemment utilisées pour l'injection / le chargement dynamique) et leur poids
    private static readonly Dictionary<string, int> ImportsSensibles = new(StringComparer.Ordinal)
    {
        ["VirtualAlloc"] = 3,
        ["VirtualAllocEx"] = 8,
        ["VirtualProtect"] = 3,
        ["VirtualProtectEx"] = 6,
        ["WriteProcessMemory"] = 10,
        ["ReadProcessMemory"] = 4,
        ["CreateRemoteThread"] = 12,
        ["CreateRemoteThreadEx"] = 12,
        ["NtUnmapViewOfSection"] = 12,
        ["NtWriteVirtualMemory"] = 10,
        ["QueueUserAPC"] = 6,
        ["SetThreadContext"] = 6,
        ["LoadLibraryA"] = 2,
        ["LoadLibraryW"] = 2,
        ["GetProcAddress"] = 2,
        ["SetWindowsHookExA"] = 8,
        ["SetWindowsHookExW"] = 8,
    };

    public string Name => "PE statique";

    public async Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(report.FullPath) || report.SizeBytes < 64)
                return Array.Empty<Indicator>();

            await using var stream = new FileStream(
                report.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                bufferSize: 4096, useAsync: true);

            return AnalyzeStream(stream, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // Fichier verrouillé, bloqué par un autre antivirus, illisible... : aucun indicateur, aucune exception
            return Array.Empty<Indicator>();
        }
    }

    // Analyse un flux (lisible et positionnable) contenant un PE. Renvoie une liste vide
    // si le contenu n'est pas un PE valide ou est corrompu. Utile aussi pour analyser un PE en mémoire.
    public IReadOnlyList<Indicator> AnalyzeStream(Stream stream, CancellationToken ct = default)
    {
        var indicators = new List<Indicator>();

        try
        {
            // Contrôle rapide de la signature MZ avant de solliciter le parseur
            stream.Position = 0;
            if (stream.ReadByte() != 'M' || stream.ReadByte() != 'Z')
                return indicators;
            stream.Position = 0;

            // PEReader valide aussi la signature "PE" suivie de deux octets nuls et lève BadImageFormatException sinon
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (pe.PEHeaders.PEHeader is null)
                return indicators; // pas un exécutable PE (ex. fichier objet COFF)

            ct.ThrowIfCancellationRequested();
            AnalyzeSections(pe, indicators, ct);
            try
            {
                AnalyzeImports(pe, indicators, ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // Table d'imports corrompue : on conserve les indicateurs déjà obtenus sur les sections
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // PE corrompu ou tronqué : aucun indicateur, et surtout aucune exception
            return new List<Indicator>();
        }

        return indicators;
    }

    private void AnalyzeSections(PEReader pe, List<Indicator> indicators, CancellationToken ct)
    {
        foreach (var section in pe.PEHeaders.SectionHeaders)
        {
            ct.ThrowIfCancellationRequested();

            bool executable = section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute);
            bool inscriptible = section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite);
            string nom = Assainir(section.Name);

            if (executable && inscriptible)
                indicators.Add(new Indicator(Name,
                    $"Section « {nom} » à la fois inscriptible et exécutable (RWX) : code auto-modifiable ou injecté", 15));

            if (!executable) continue;

            // Déséquilibre taille virtuelle / taille brute (code décompressé en mémoire au lancement)
            long brute = section.SizeOfRawData;
            long virtuelle = section.VirtualSize;
            if (virtuelle >= 64 * 1024 && (brute == 0 || virtuelle > brute * 10))
                indicators.Add(new Indicator(Name,
                    $"Section exécutable « {nom} » : taille virtuelle ({virtuelle} o) très supérieure à la taille sur disque ({brute} o), typique d'un packer", 10));

            if (brute >= TailleMiniSection && brute <= TailleMaxLectureSection)
            {
                double entropie = EntropieSection(pe, section);
                if (entropie >= SeuilEntropieSection)
                    indicators.Add(new Indicator(Name,
                        $"Section exécutable « {nom} » à très haute entropie ({entropie:F2}/8) : code probablement packé ou chiffré", 20));
            }
        }
    }

    private static double EntropieSection(PEReader pe, SectionHeader section)
    {
        var bloc = LireDonnees(pe, section.VirtualAddress);
        if (bloc.Length == 0) return 0;

        var contenu = bloc.GetContent(0, Math.Min(bloc.Length, section.SizeOfRawData));
        return ShannonEntropy(contenu.AsSpan());
    }

    // Entropie de Shannon, de 0 (contenu répétitif) à 8 (contenu aléatoire)
    internal static double ShannonEntropy(ReadOnlySpan<byte> donnees)
    {
        if (donnees.IsEmpty) return 0;

        Span<long> compteurs = stackalloc long[256];
        foreach (byte b in donnees)
            compteurs[b]++;

        double entropie = 0;
        foreach (long c in compteurs)
        {
            if (c == 0) continue;
            double p = (double)c / donnees.Length;
            entropie -= p * Math.Log2(p);
        }
        return entropie;
    }

    private void AnalyzeImports(PEReader pe, List<Indicator> indicators, CancellationToken ct)
    {
        var imports = LireImports(pe, ct, out int total);

        if (total == 0)
        {
            indicators.Add(new Indicator(Name,
                "Aucun import détecté : les API sont probablement résolues dynamiquement (packer ou shellcode)", 15));
            return;
        }

        var trouves = new List<string>();
        int points = 0;
        foreach (string nom in imports.OrderBy(n => n, StringComparer.Ordinal))
        {
            if (ImportsSensibles.TryGetValue(nom, out int poids))
            {
                trouves.Add(nom);
                points += poids;
            }
        }

        if (trouves.Count > 0)
            indicators.Add(new Indicator(Name,
                $"Imports sensibles ({trouves.Count}) : {string.Join(", ", trouves)}", Math.Min(points, PointsMaxImports)));
    }

    // Parcourt la table d'imports (IAT) et renvoie les noms d'API importées par nom
    private static HashSet<string> LireImports(PEReader pe, CancellationToken ct, out int total)
    {
        var noms = new HashSet<string>(StringComparer.Ordinal);
        total = 0;

        var entete = pe.PEHeaders.PEHeader!;
        int rvaImports = entete.ImportTableDirectory.RelativeVirtualAddress;
        if (rvaImports == 0 || entete.ImportTableDirectory.Size == 0) return noms;

        bool pe32Plus = entete.Magic == PEMagic.PE32Plus;
        int tailleThunk = pe32Plus ? 8 : 4;

        var tableau = LireDonnees(pe, rvaImports);
        if (tableau.Length == 0) return noms;
        var lecteur = tableau.GetReader();

        for (int dll = 0; dll < MaxDll && lecteur.RemainingBytes >= 20; dll++)
        {
            ct.ThrowIfCancellationRequested();

            uint originalFirstThunk = lecteur.ReadUInt32();
            lecteur.ReadUInt32(); // TimeDateStamp
            lecteur.ReadUInt32(); // ForwarderChain
            uint nomDll = lecteur.ReadUInt32();
            uint firstThunk = lecteur.ReadUInt32();

            if (originalFirstThunk == 0 && nomDll == 0 && firstThunk == 0) break; // descripteur nul : fin

            uint rvaThunks = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var thunks = LireDonnees(pe, (int)rvaThunks);
            if (thunks.Length == 0) continue;
            var lt = thunks.GetReader();

            while (lt.RemainingBytes >= tailleThunk && total < MaxImports)
            {
                ulong valeur = pe32Plus ? lt.ReadUInt64() : lt.ReadUInt32();
                if (valeur == 0) break;
                total++;

                bool ordinal = pe32Plus ? (valeur & 0x8000000000000000UL) != 0 : (valeur & 0x80000000UL) != 0;
                if (ordinal) continue;

                string? nom = LireNomImport(pe, (int)(valeur & 0x7FFFFFFF));
                if (nom is not null) noms.Add(nom);
            }

            if (total >= MaxImports) break;
        }

        return noms;
    }

    // Lit une entrée "hint/name" (Hint sur 2 octets puis nom ASCII terminé par 0)
    private static string? LireNomImport(PEReader pe, int rva)
    {
        var bloc = LireDonnees(pe, rva);
        if (bloc.Length <= 2) return null;

        var octets = bloc.GetContent(2, Math.Min(bloc.Length - 2, 256));
        int fin = octets.IndexOf((byte)0);
        if (fin <= 0) return null;

        return Encoding.ASCII.GetString(octets.AsSpan(0, fin));
    }

    // GetSectionData lève une exception si la RVA ne tombe dans aucune section (PE malformé) : on renvoie un bloc vide
    private static PEMemoryBlock LireDonnees(PEReader pe, int rva)
    {
        try
        {
            return pe.GetSectionData(rva);
        }
        catch (ArgumentOutOfRangeException)
        {
            return default;
        }
    }

    // Garde uniquement les caractères ASCII imprimables d'un nom provenant du fichier
    private static string Assainir(string valeur)
    {
        var sb = new StringBuilder(valeur.Length);
        foreach (char c in valeur)
            sb.Append(c is >= ' ' and <= '~' ? c : '?');
        return sb.Length == 0 ? "?" : sb.ToString();
    }
}
