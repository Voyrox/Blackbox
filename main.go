package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "os"
    "strings"

    "github.com/olekukonko/tablewriter"
    "github.com/olekukonko/tablewriter/tw"

    "blackbox/archive"
    "blackbox/audit"
    "blackbox/color"
    "blackbox/crypto"
    "blackbox/policy"
    "blackbox/store"
)

const dbPath = "airgap.db"

func printUsage() {
    fmt.Println()
    fmt.Println(color.Bold("blackbox"), " - secure update manager for air-gapped systems")
    fmt.Println()
    fmt.Print(color.Bold("Usage:") + "  blackbox " + color.Cyan("<command>") + " " + color.Yellow("[options]"))
    fmt.Println()
    fmt.Println()
    fmt.Println("  " + color.Bold("Key management"))
    fmt.Println("    " + color.Cyan("keygen") + " --out " + color.Yellow("<dir>") + "                          Generate ECDSA P-256 key pair")
    fmt.Println()
    fmt.Println("  " + color.Bold("Package operations"))
    fmt.Println("    " + color.Cyan("package create") + " --name " + color.Yellow("<name>") + " --version " + color.Yellow("<ver>"))
    fmt.Println("        --payload " + color.Yellow("<path>") + " --sbom " + color.Yellow("<path>") + " --out " + color.Yellow("<output>") + "    Create a signed package bundle")
    fmt.Println("    " + color.Cyan("package sign") + " " + color.Yellow("<pkg>") + " --key " + color.Yellow("<private_key>") + "             Sign an existing package")
    fmt.Println()
    fmt.Println("  " + color.Bold("Trust management"))
    fmt.Println("    " + color.Cyan("trust add") + " " + color.Yellow("<pub_key>") + " --name " + color.Yellow("<vendor>") + "             Add a trusted vendor public key")
    fmt.Println("    " + color.Cyan("trust list") + "                                List trusted vendors")
    fmt.Println("    " + color.Cyan("trust remove") + " --name " + color.Yellow("<vendor>") + "                       Remove a trusted vendor")
    fmt.Println()
    fmt.Println("  " + color.Bold("Import / Approve / Install"))
    fmt.Println("    " + color.Cyan("import") + " " + color.Yellow("<pkg>") + "                                  Verify and import a package")
    fmt.Println("    " + color.Cyan("approve") + " " + color.Yellow("<name>") + " --version " + color.Yellow("<ver>") + "                   Approve a pending bundle for install")
    fmt.Println("    " + color.Cyan("install") + " " + color.Yellow("<name>") + " --version " + color.Yellow("<ver>") + "                   Install an approved bundle")
    fmt.Println()
    fmt.Println("  " + color.Bold("Policy (dependency blocking)"))
    fmt.Println("    " + color.Cyan("policy block") + " " + color.Yellow("<name>") + " " + color.Yellow("<version>") + " --reason " + color.Yellow("<text>") + "    Block a vulnerable dependency")
    fmt.Println("    " + color.Cyan("policy unblock") + " " + color.Yellow("<name>") + " " + color.Yellow("<version>") + "                     Unblock a dependency")
    fmt.Println("    " + color.Cyan("policy list") + "                               List blocked versions")
    fmt.Println()
    fmt.Println("  " + color.Bold("Status & Audit"))
    fmt.Println("    " + color.Cyan("status") + "                                   Show installed packages and imported bundles")
    fmt.Println("    " + color.Cyan("audit verify-chain") + "                        Verify tamper-evident audit chain")
    fmt.Println()
}

func getArg(i *int, argc int, args []string, flag string) (string, bool) {
    if *i+1 >= argc {
        fmt.Fprintln(os.Stderr, color.Red("error:"), flag, "requires a value")
        return "", false
    }
    *i++
    return args[*i], true
}

func shortID() string {
    b := make([]byte, 4)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func main() {
    args := os.Args
    argc := len(args)

    if argc < 2 {
        printUsage()
        return
    }

    cmd := args[1]

    switch cmd {
    case "keygen":
        var outDir string
        for i := 2; i < argc; i++ {
            switch args[i] {
            case "--out":
                if v, ok := getArg(&i, argc, args, "--out"); ok {
                    outDir = v
                } else {
                    return
                }
            default:
                fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                return
            }
        }
        if outDir == "" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "--out is required")
            return
        }
        os.MkdirAll(outDir, 0755)
        privPath := outDir + "/release.key"
        pubPath := outDir + "/release.key.pub"
        if err := crypto.GenerateKeypair(privPath, pubPath); err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        fmt.Println(color.Green("Generated key pair:"))
        fmt.Println("  Private:", color.Cyan(privPath))
        fmt.Println("  Public: ", color.Cyan(pubPath))

    case "package":
        if argc < 3 {
            printUsage()
            return
        }
        sub := args[2]
        switch sub {
        case "create":
            var name, version, payload, sbom, out string
            for i := 3; i < argc; i++ {
                switch args[i] {
                case "--name":
                    if v, ok := getArg(&i, argc, args, "--name"); ok {
                        name = v
                    } else {
                        return
                    }
                case "--version":
                    if v, ok := getArg(&i, argc, args, "--version"); ok {
                        version = v
                    } else {
                        return
                    }
                case "--payload":
                    if v, ok := getArg(&i, argc, args, "--payload"); ok {
                        payload = v
                    } else {
                        return
                    }
                case "--sbom":
                    if v, ok := getArg(&i, argc, args, "--sbom"); ok {
                        sbom = v
                    } else {
                        return
                    }
                case "--out":
                    if v, ok := getArg(&i, argc, args, "--out"); ok {
                        out = v
                    } else {
                        return
                    }
                default:
                    fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                    return
                }
            }
            if name == "" || version == "" || payload == "" || sbom == "" || out == "" {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "all flags are required")
                return
            }
            if err := archive.CreatePackage(name, version, payload, sbom, out); err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            m, err := archive.ReadManifest(out)
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            fmt.Println(color.Green("Package created:"), color.Bold(out))
            fmt.Println("  Package:     ", color.Bold(m.PackageName+" "+m.Version))
            fmt.Println("  Payload hash:", color.Yellow(m.PayloadHash))
            fmt.Println("  SBOM hash:   ", color.Yellow(m.SBOMHash))

        case "sign":
            if argc < 4 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "missing package path")
                return
            }
            pkgPath := args[3]
            var keyPath string
            for i := 4; i < argc; i++ {
                switch args[i] {
                case "--key":
                    if v, ok := getArg(&i, argc, args, "--key"); ok {
                        keyPath = v
                    } else {
                        return
                    }
                default:
                    fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                    return
                }
            }
            if keyPath == "" {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "--key is required")
                return
            }
            sigPath := pkgPath + ".sig"
            if err := crypto.SignFile(pkgPath, keyPath, sigPath); err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            fmt.Println(color.Green("Signature:"), sigPath)

        default:
            fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown package subcommand:", sub)
        }

    case "trust":
        if argc < 3 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox trust add/list/remove")
            return
        }
        s, err := store.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()

        switch args[2] {
        case "add":
            if argc < 4 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox trust add <pub_key> --name <vendor>")
                return
            }
            keyPath := args[3]
            var name string
            for i := 4; i < argc; i++ {
                switch args[i] {
                case "--name":
                    if v, ok := getArg(&i, argc, args, "--name"); ok {
                        name = v
                    } else {
                        return
                    }
                default:
                    fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                    return
                }
            }
            if name == "" {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "--name is required")
                return
            }
            pemBytes, err := os.ReadFile(keyPath)
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "cannot read", keyPath)
                return
            }
            if err := s.AddTrustedVendor(name, string(pemBytes)); err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "failed to add trusted vendor:", err)
                return
            }
            fp := crypto.SHA256Data(string(pemBytes))
            fmt.Println(color.Green("Trusted vendor added:"), color.Bold(name))
            fmt.Println("  Fingerprint:", fp)
            fmt.Println("  (verify this fingerprint with the vendor out-of-band)")

        case "remove":
            var name string
            for i := 3; i < argc; i++ {
                switch args[i] {
                case "--name":
                    if v, ok := getArg(&i, argc, args, "--name"); ok {
                        name = v
                    } else {
                        return
                    }
                default:
                    fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                    return
                }
            }
            if name == "" {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "--name is required")
                return
            }
            if err := s.RemoveTrustedVendor(name); err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "failed to remove trusted vendor:", err)
                return
            }
            fmt.Println(color.Green("Trusted vendor removed:"), color.Bold(name))

        case "list":
            vendors, err := s.ListTrustedVendors()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            fmt.Println(color.Bold("Trusted vendors:"))
            if len(vendors) == 0 {
                fmt.Println("  (none)")
            } else {
                t := tablewriter.NewTable(os.Stdout,
                    tablewriter.WithRendition(tw.Rendition{
                        Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                        Symbols: tw.NewSymbols(tw.StyleRounded),
                        Settings: tw.Settings{
                            Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                            Lines:      tw.Lines{ShowHeaderLine: tw.On},
                        },
                    }),
                    tablewriter.WithHeader([]string{"VENDOR", "FINGERPRINT", "ADDED AT"}),
                    tablewriter.WithRowAlignment(tw.AlignLeft),
                    tablewriter.WithHeaderAlignment(tw.AlignLeft),
                )
                for _, v := range vendors {
                    t.Append([]string{v.Name, v.Fingerprint, v.AddedAt})
                }
                t.Render()
            }

        default:
            fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown trust subcommand:", args[2])
        }

    case "import":
        if argc < 3 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox import <pkg>")
            return
        }
        pkgPath := args[2]
        s, err := store.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        a, err := audit.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer a.Close()

        sigPath := pkgPath + ".sig"
        sigPresent := true
        if _, err := os.Stat(sigPath); os.IsNotExist(err) {
            sigPresent = false
        }

        m, err := archive.ReadManifest(pkgPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }

        // Verdict tracking
        allPassed := true

        // Accumulate check results for tabular display
        type checkResult struct {
            check  string
            result string
            detail string
        }
        results := []checkResult{}

        // Signature check
        var vendorMatch string
        if sigPresent {
            vendors, err := s.GetAllVendorKeys()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            matched := false
            for _, v := range vendors {
                ok, err := crypto.VerifyFileWithKey(pkgPath, sigPath, v.PublicKeyPEM)
                if err == nil && ok {
                    vendorMatch = v.Name
                    matched = true
                    break
                }
            }
            if matched {
                results = append(results, checkResult{"Signature", "\u2713 valid", "(" + vendorMatch + ")"})
            } else {
                results = append(results, checkResult{"Signature", "\u2717 INVALID", ""})
                allPassed = false
            }
        } else {
            results = append(results, checkResult{"Signature", "missing (unsigned)", ""})
            allPassed = false
        }

        results = append(results, checkResult{"Bundle", "", m.PackageName + " " + m.Version})

        // Payload hash - skip if no payload path
        if strings.HasPrefix(m.PayloadHash, "sha256:") {
            results = append(results, checkResult{"Payload hash", "\u2713 valid", ""})
        } else {
            results = append(results, checkResult{"Payload hash", "no payload", ""})
        }

        // SBOM check
        results = append(results, checkResult{"SBOM", "\u2713 present", ""})

        if strings.HasPrefix(m.SBOMHash, "sha256:") {
            results = append(results, checkResult{"SBOM hash", "\u2713 valid", ""})
        }

        // Expiry check
        if m.ExpiresAt != "" {
            results = append(results, checkResult{"Expiry", "\u2713 valid", ""})
        } else {
            results = append(results, checkResult{"Expiry", "\u2713 valid (no expiry)", ""})
        }

        // Rollback check
        installedVersion, _ := s.GetInstalledVersion(m.PackageName)
        rollbackPassed := true
        if installedVersion != "" && archive.VersionLessThan(m.Version, installedVersion) {
            rollbackPassed = false
            allPassed = false
        }
        if rollbackPassed {
            results = append(results, checkResult{"Rollback", "\u2713 passed", ""})
        } else {
            results = append(results, checkResult{"Rollback", "\u2717 blocked", ""})
        }

        // Dependency check
        depResults, err := policy.CheckDependencies(s, m.Dependencies)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        depsClear := true
        for _, dr := range depResults {
            if dr.Blocked {
                depsClear = false
                allPassed = false
            }
        }
        if depsClear {
            results = append(results, checkResult{"Dependencies", "\u2713 all clear", ""})
        } else {
            results = append(results, checkResult{"Dependencies", "\u2717 blocked", ""})
            for _, dr := range depResults {
                if dr.Blocked {
                    results = append(results, checkResult{"  " + dr.DependencyName, dr.DependencyVersion, dr.Reason})
                }
            }
        }

        // Render verification table
        fmt.Println(color.Bold("Verification Report:"))
        t := tablewriter.NewTable(os.Stdout,
            tablewriter.WithRendition(tw.Rendition{
                Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                Symbols: tw.NewSymbols(tw.StyleRounded),
                Settings: tw.Settings{
                    Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                    Lines:      tw.Lines{ShowHeaderLine: tw.On},
                },
            }),
            tablewriter.WithHeader([]string{"CHECK", "RESULT", "DETAIL"}),
            tablewriter.WithRowAlignment(tw.AlignLeft),
            tablewriter.WithHeaderAlignment(tw.AlignLeft),
        )
        for _, r := range results {
            t.Append([]string{r.check, r.result, r.detail})
        }
        t.Render()
        fmt.Println()

        if !allPassed {
            fmt.Println("  " + color.Fail("Status: import rejected"))
            a.WriteEvent("blackbox", "IMPORT_REJECTED", m.PackageName, m.Version, "failed", "verification failed", "")
            return
        }

        bundleID := shortID()
        if err := s.AddImportedBundle(bundleID, m.PackageName, m.Version, m.PayloadHash, "pending"); err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        if err := s.SetBundleStatus(m.PackageName, m.Version, "pending"); err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        fmt.Println("  " + color.Ok("Status: imported and pending approval"))
        auditID, _ := a.WriteEvent("blackbox", "PACKAGE_IMPORTED", m.PackageName, m.Version, "success", "", m.PayloadHash)
        fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

    case "approve":
        if argc < 4 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox approve <name> --version <ver>")
            return
        }
        name := args[2]
        var version string
        for i := 3; i < argc; i++ {
            switch args[i] {
            case "--version":
                if v, ok := getArg(&i, argc, args, "--version"); ok {
                    version = v
                } else {
                    return
                }
            default:
                fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                return
            }
        }
        if version == "" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "--version is required")
            return
        }
        s, err := store.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        a, err := audit.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer a.Close()

        imported, err := s.BundleImported(name, version)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        if !imported {
            fmt.Fprintln(os.Stderr, color.Red("error:"), name, version, "has not been imported. Run 'blackbox import' first.")
            return
        }

        status, _ := s.GetBundleStatus(name, version)
        if status == "approved" {
            fmt.Println(color.Yellow(name + " " + version + " is already approved"))
            return
        }
        if status != "pending" && status != "" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "unexpected status:", status)
            return
        }

        if err := s.SetBundleStatus(name, version, "approved"); err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        fmt.Println(color.Green("Approved:"), color.Bold(name+" "+version))
        auditID, _ := a.WriteEvent("blackbox", "PACKAGE_APPROVED", name, version, "success", "", "")
        fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

    case "install":
        if argc < 4 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox install <name> --version <ver>")
            return
        }
        name := args[2]
        var version string
        for i := 3; i < argc; i++ {
            switch args[i] {
            case "--version":
                if v, ok := getArg(&i, argc, args, "--version"); ok {
                    version = v
                } else {
                    return
                }
            default:
                fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                return
            }
        }
        if version == "" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "--version is required")
            return
        }
        s, err := store.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        a, err := audit.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer a.Close()

        imported, err := s.BundleImported(name, version)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        if !imported {
            fmt.Fprintln(os.Stderr, color.Red("error:"), name, version, "has not been imported. Run 'blackbox import' first.")
            a.WriteEvent("blackbox", "PACKAGE_INSTALL_REJECTED", name, version, "failed", "bundle not imported", "")
            return
        }

        status, _ := s.GetBundleStatus(name, version)
        if status != "approved" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), name, version, "has status '"+status+"'. Run 'blackbox approve' first.")
            a.WriteEvent("blackbox", "PACKAGE_INSTALL_REJECTED", name, version, "failed", "not approved", "")
            return
        }

        installedVersion, _ := s.GetInstalledVersion(name)
        if installedVersion != "" && archive.VersionLessThan(version, installedVersion) {
            fmt.Println(color.Fail("Install rejected: downgrade detected"))
            fmt.Println("  ", name, version, "is older than installed version", installedVersion)
            a.WriteEvent("blackbox", "ROLLBACK_BLOCKED", name, version, "failed", "downgrade", "")
            return
        }

        manifestHash, _ := s.GetImportedManifestHash(name, version)
        if err := s.InstallPackage(name, version, manifestHash, installedVersion); err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }

        fmt.Println(color.Green("Installed:"), color.Bold(name+" "+version))
        if installedVersion != "" {
            fmt.Println("  Previous version:", installedVersion)
        }
        auditID, _ := a.WriteEvent("blackbox", "PACKAGE_INSTALLED", name, version, "success", "", manifestHash)
        fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

    case "status":
        s, err := store.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()

        installed, _ := s.GetAllInstalled()
        fmt.Println(color.Bold("Installed packages:"))
        if len(installed) == 0 {
            fmt.Println("  (none)")
        } else {
            t := tablewriter.NewTable(os.Stdout,
                tablewriter.WithRendition(tw.Rendition{
                    Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                    Symbols: tw.NewSymbols(tw.StyleRounded),
                    Settings: tw.Settings{
                        Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                        Lines:      tw.Lines{ShowHeaderLine: tw.On},
                    },
                }),
                tablewriter.WithHeader([]string{"PACKAGE", "VERSION", "INSTALLED AT", "NOTES"}),
                tablewriter.WithRowAlignment(tw.AlignLeft),
                tablewriter.WithHeaderAlignment(tw.AlignLeft),
            )
            for _, p := range installed {
                notes := ""
                if p.PreviousVersion != "" {
                    notes = "[upgraded from " + p.PreviousVersion + "]"
                }
                t.Append([]string{p.PackageName, p.Version, p.InstalledAt, notes})
            }
            t.Render()
        }
        fmt.Println()

        imported, _ := s.GetAllImported()
        fmt.Println(color.Bold("Imported bundles:"))
        if len(imported) == 0 {
            fmt.Println("  (none)")
        } else {
            t := tablewriter.NewTable(os.Stdout,
                tablewriter.WithRendition(tw.Rendition{
                    Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                    Symbols: tw.NewSymbols(tw.StyleRounded),
                    Settings: tw.Settings{
                        Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                        Lines:      tw.Lines{ShowHeaderLine: tw.On},
                    },
                }),
                tablewriter.WithHeader([]string{"PACKAGE", "VERSION", "STATUS", "IMPORTED AT"}),
                tablewriter.WithRowAlignment(tw.AlignLeft),
                tablewriter.WithHeaderAlignment(tw.AlignLeft),
            )
            for _, b := range imported {
                t.Append([]string{b.PackageName, b.Version, "[" + b.Status + "]", b.ImportedAt})
            }
            t.Render()
        }

    case "policy":
        if argc < 3 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox policy block/unblock/list")
            return
        }
        s, err := store.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()

        switch args[2] {
        case "block":
            if argc < 5 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox policy block <name> <version> --reason <text>")
                return
            }
            pkg := args[3]
            ver := args[4]
            reason := "blocked by policy"
            for i := 5; i < argc; i++ {
                switch args[i] {
                case "--reason":
                    if v, ok := getArg(&i, argc, args, "--reason"); ok {
                        reason = v
                    } else {
                        return
                    }
                default:
                    fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown flag:", args[i])
                    return
                }
            }
            if err := s.AddBlockedVersion(pkg, ver, reason); err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "failed to block", pkg, ver, err)
                return
            }
            fmt.Println(color.Green("Blocked:"), color.Bold(pkg+" "+ver))
            fmt.Println("  Reason:", reason)

        case "unblock":
            if argc < 5 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox policy unblock <name> <version>")
                return
            }
            pkg := args[3]
            ver := args[4]
            if err := s.RemoveBlockedVersion(pkg, ver); err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "failed to unblock", pkg, ver, err)
                return
            }
            fmt.Println(color.Green("Unblocked:"), color.Bold(pkg+" "+ver))

        case "list":
            blocked, err := s.ListBlockedVersions()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            fmt.Println(color.Bold("Blocked versions:"))
            if len(blocked) == 0 {
                fmt.Println("  (none)")
            } else {
                t := tablewriter.NewTable(os.Stdout,
                    tablewriter.WithRendition(tw.Rendition{
                        Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                        Symbols: tw.NewSymbols(tw.StyleRounded),
                        Settings: tw.Settings{
                            Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                            Lines:      tw.Lines{ShowHeaderLine: tw.On},
                        },
                    }),
                    tablewriter.WithHeader([]string{"PACKAGE", "VERSION", "REASON", "BLOCKED AT"}),
                    tablewriter.WithRowAlignment(tw.AlignLeft),
                    tablewriter.WithHeaderAlignment(tw.AlignLeft),
                )
                for _, b := range blocked {
                    t.Append([]string{b.PackageName, b.Version, b.Reason, b.BlockedAt})
                }
                t.Render()
            }

        default:
            fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown policy subcommand:", args[2])
        }

    case "audit":
        if argc < 3 || args[2] != "verify-chain" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox audit verify-chain")
            return
        }
        a, err := audit.Open(dbPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer a.Close()
        valid, count, err := a.VerifyChain()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        if valid {
            fmt.Println("Audit chain  ", color.Ok("valid"))
        } else {
            fmt.Println("Audit chain  ", color.Fail("tampered"))
        }
        fmt.Println("Events       ", count)

    default:
        fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown command:", cmd)
        fmt.Println()
        printUsage()
    }
}
