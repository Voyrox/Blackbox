package main

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
    "strings"
    "time"

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

type checkResult struct {
	check  string
	result string
	detail string
}



func verifyPackage(s *store.Store, pkgPath, sigPath string, m *archive.Manifest) (allPassed bool, results []checkResult) {
	allPassed = true

	sigPresent := true
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		sigPresent = false
	}

	if sigPresent {
		vendors, err := s.GetAllVendorKeys()
		if err != nil {
			results = append(results, checkResult{"Signature", "\u2717 error", err.Error()})
			allPassed = false
		} else {
			matched := false
			for _, v := range vendors {
				ok, err := crypto.VerifyFileWithKey(pkgPath, sigPath, v.PublicKeyPEM)
				if err == nil && ok {
					results = append(results, checkResult{"Signature", "\u2713 valid", "(" + v.Name + ")"})
					matched = true
					break
				}
			}
			if !matched {
				results = append(results, checkResult{"Signature", "\u2717 INVALID", ""})
				allPassed = false
			}
		}
	} else {
		results = append(results, checkResult{"Signature", "missing (unsigned)", ""})
		allPassed = false
	}

	results = append(results, checkResult{"Bundle", "", m.PackageName + " " + m.Version})

	if strings.HasPrefix(m.PayloadHash, "sha256:") {
		expected := strings.TrimPrefix(m.PayloadHash, "sha256:")
		computed, err := archive.HashArchiveDir(pkgPath, "payload")
		if err != nil {
			results = append(results, checkResult{"Payload hash", "\u2717 error", err.Error()})
			allPassed = false
		} else if computed == expected {
			results = append(results, checkResult{"Payload hash", "\u2713 valid", ""})
		} else {
			results = append(results, checkResult{"Payload hash", "\u2717 hash mismatch", "expected " + expected[:12] + "..."})
			allPassed = false
		}
	} else {
		results = append(results, checkResult{"Payload hash", "no payload", ""})
	}

	sbomData, sbomErr := archive.ReadFileFromArchive(pkgPath, "metadata/sbom.spdx.json")
	if sbomErr != nil {
		results = append(results, checkResult{"SBOM", "\u2717 missing", sbomErr.Error()})
		allPassed = false
	} else {
		results = append(results, checkResult{"SBOM", "\u2713 present", ""})
		if strings.HasPrefix(m.SBOMHash, "sha256:") {
			expected := strings.TrimPrefix(m.SBOMHash, "sha256:")
			sbomHash := fmt.Sprintf("%x", sha256.Sum256(sbomData))
			if sbomHash == expected {
				results = append(results, checkResult{"SBOM hash", "\u2713 valid", ""})
			} else {
				results = append(results, checkResult{"SBOM hash", "\u2717 hash mismatch", "expected " + expected[:12] + "..."})
				allPassed = false
			}
		}
	}

	if m.ExpiresAt != "" {
		expiryTime, err := time.Parse(time.RFC3339, m.ExpiresAt)
		if err != nil {
			results = append(results, checkResult{"Expiry", "\u2717 invalid date", err.Error()})
			allPassed = false
		} else if time.Now().UTC().After(expiryTime) {
			results = append(results, checkResult{"Expiry", "\u2717 expired", "expired " + expiryTime.Format("2006-01-02")})
			allPassed = false
		} else {
			results = append(results, checkResult{"Expiry", "\u2713 valid", ""})
		}
	} else {
		results = append(results, checkResult{"Expiry", "\u2713 valid (no expiry)", ""})
	}

	installedVersion, _ := s.GetInstalledVersion(m.PackageName)
	if installedVersion != "" && archive.VersionLessThan(m.Version, installedVersion) {
		results = append(results, checkResult{"Rollback", "\u2717 blocked", ""})
		allPassed = false
	} else {
		results = append(results, checkResult{"Rollback", "\u2713 passed", ""})
	}

	depResults, err := policy.CheckDependencies(s, m.Dependencies)
	if err != nil {
		results = append(results, checkResult{"Dependencies", "\u2717 error", err.Error()})
		allPassed = false
	} else {
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
	}

	return
}

func renderVerificationTable(results []checkResult) {
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
}

func handleInstallPackage(s *store.Store, a *audit.AuditLog, pkgPath string) {
	m, err := archive.ReadManifest(pkgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, color.Red("error:"), err)
		return
	}

	sigPath := pkgPath + ".sig"
	allPassed, results := verifyPackage(s, pkgPath, sigPath, m)
	renderVerificationTable(results)

	if !allPassed {
		fmt.Println("  " + color.Fail("Status: install rejected"))
		a.WriteEvent("blackbox", "INSTALL_REJECTED", m.PackageName, m.Version, "failed", "verification failed", metaWithState(s, ""))
		return
	}

	name := m.PackageName
	version := m.Version

	imported, _ := s.BundleImported(name, version)
	if !imported {
		bundleID := shortID()
		if err := s.AddImportedBundle(bundleID, name, version, m.PayloadHash, "approved"); err != nil {
			fmt.Fprintln(os.Stderr, color.Red("error:"), err)
			return
		}
		if err := s.SetBundleStatus(name, version, "approved"); err != nil {
			fmt.Fprintln(os.Stderr, color.Red("error:"), err)
			return
		}
		auditID, _ := a.WriteEvent("blackbox", "PACKAGE_IMPORTED", name, version, "success", "", metaWithState(s, m.PayloadHash))
		fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)
	} else {
		status, _ := s.GetBundleStatus(name, version)
		if status != "approved" {
			s.SetBundleStatus(name, version, "approved")
			auditID, _ := a.WriteEvent("blackbox", "PACKAGE_APPROVED", name, version, "success", "", metaWithState(s, ""))
			fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)
		}
	}

	installedVersion, _ := s.GetInstalledVersion(name)
	if err := s.InstallPackage(name, version, m.PayloadHash, installedVersion); err != nil {
		fmt.Fprintln(os.Stderr, color.Red("error:"), err)
		return
	}

	fmt.Println(color.Green("Installed:"), color.Bold(name+" "+version))
	if installedVersion != "" {
		fmt.Println("  Previous version:", installedVersion)
	}
	auditID, _ := a.WriteEvent("blackbox", "PACKAGE_INSTALLED", name, version, "success", "", metaWithState(s, m.PayloadHash))
	fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)
}

func handleInstall(s *store.Store, a *audit.AuditLog, name, version string) {
	imported, err := s.BundleImported(name, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, color.Red("error:"), err)
		return
	}
	if !imported {
		fmt.Fprintln(os.Stderr, color.Red("error:"), name, version, "has not been imported. Run 'blackbox import' first.")
		a.WriteEvent("blackbox", "PACKAGE_INSTALL_REJECTED", name, version, "failed", "bundle not imported", metaWithState(s, ""))
		return
	}

	status, _ := s.GetBundleStatus(name, version)
	if status != "approved" {
		fmt.Fprintln(os.Stderr, color.Red("error:"), name, version, "has status '"+status+"'. Run 'blackbox approve' first.")
		a.WriteEvent("blackbox", "PACKAGE_INSTALL_REJECTED", name, version, "failed", "not approved", metaWithState(s, ""))
		return
	}

	installedVersion, _ := s.GetInstalledVersion(name)
	if installedVersion != "" && archive.VersionLessThan(version, installedVersion) {
		fmt.Println(color.Fail("Install rejected: downgrade detected"))
		fmt.Println("  ", name, version, "is older than installed version", installedVersion)
		a.WriteEvent("blackbox", "ROLLBACK_BLOCKED", name, version, "failed", "downgrade", metaWithState(s, ""))
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
	auditID, _ := a.WriteEvent("blackbox", "PACKAGE_INSTALLED", name, version, "success", "", metaWithState(s, manifestHash))
	fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)
}

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
    fmt.Println("    " + color.Cyan("package inspect") + " " + color.Yellow("<pkg>") + "                              View package manifest fields")
    fmt.Println("    " + color.Cyan("package verify") + " " + color.Yellow("<pkg>") + "                              Verify a package (dry run)")
    fmt.Println("    " + color.Cyan("package import") + " " + color.Yellow("<pkg>") + "                              Verify and import a package (staged)")
    fmt.Println("    " + color.Cyan("package install") + " " + color.Yellow("<pkg>") + "                              Verify, import, approve, and install in one step")
    fmt.Println("    " + color.Cyan("package install") + " " + color.Yellow("<name>") + " --version " + color.Yellow("<ver>") + "              Install an already-imported bundle")
    fmt.Println()
    fmt.Println("  " + color.Bold("Trust management"))
    fmt.Println("    " + color.Cyan("trust add") + " " + color.Yellow("<pub_key>") + " --name " + color.Yellow("<vendor>") + "             Add a trusted vendor public key")
    fmt.Println("    " + color.Cyan("trust list") + "                                List trusted vendors")
    fmt.Println("    " + color.Cyan("trust remove") + " --name " + color.Yellow("<vendor>") + "                       Remove a trusted vendor")
    fmt.Println()
    fmt.Println("  " + color.Bold("Import / Approve / Install (legacy aliases)"))
    fmt.Println("    " + color.Cyan("import") + " " + color.Yellow("<pkg>") + "                                  (alias for 'package import')")
    fmt.Println("    " + color.Cyan("approve") + " " + color.Yellow("<name>") + " --version " + color.Yellow("<ver>") + "                   Approve a pending bundle for install")
    fmt.Println("    " + color.Cyan("install") + " " + color.Yellow("<pkg>") + "                                  (alias for 'package install')")
    fmt.Println()
    fmt.Println("  " + color.Bold("Policy (dependency blocking)"))
    fmt.Println("    " + color.Cyan("policy block") + " " + color.Yellow("<name>") + " " + color.Yellow("<version>") + " --reason " + color.Yellow("<text>") + "    Block a vulnerable dependency")
    fmt.Println("    " + color.Cyan("policy unblock") + " " + color.Yellow("<name>") + " " + color.Yellow("<version>") + "                     Unblock a dependency")
    fmt.Println("    " + color.Cyan("policy list") + "                               List blocked versions")
    fmt.Println()
    fmt.Println("  " + color.Bold("Status & Audit"))
    fmt.Println("    " + color.Cyan("status") + "                                   Show installed packages and imported bundles")
    fmt.Println("    " + color.Cyan("audit verify-chain") + "                        Verify tamper-evident audit chain")
    fmt.Println("    " + color.Cyan("audit log") + "                                 View audit event log")
    fmt.Println()
    fmt.Println("  " + color.Bold("Database"))
    fmt.Println("    " + color.Cyan("db verify") + "                                Verify audit chain + table integrity")
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

func metaWithState(s *store.Store, meta string) string {
    sh, err := s.HashState()
    if err != nil {
        return meta + "|state:error"
    }
    if meta == "" {
        return "state:" + sh
    }
    return meta + "|state:" + sh
}

func verifyCurrentDB(s *store.Store, a *audit.AuditLog) error {
	valid, _, err := a.VerifyChain()
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("audit chain verification failed; run 'blackbox db verify'")
	}

	events, err := a.ListEvents()
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	var recordedState string
	for _, part := range strings.Split(events[0].Meta, "|") {
		if strings.HasPrefix(part, "state:") {
			recordedState = strings.TrimPrefix(part, "state:")
			break
		}
	}
	if recordedState == "" {
		return nil
	}

	currentState, err := s.HashState()
	if err != nil {
		return err
	}
	if recordedState != currentState {
		return fmt.Errorf("database state does not match audit log; run 'blackbox db verify'")
	}
	return nil
}

func openVerifiedDB() (*store.Store, *audit.AuditLog, error) {
	s, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	a, err := audit.Open(dbPath)
	if err != nil {
		s.Close()
		return nil, nil, err
	}
	if err := verifyCurrentDB(s, a); err != nil {
		a.Close()
		s.Close()
		return nil, nil, err
	}
	return s, a, nil
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

        case "inspect":
            if argc < 4 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox package inspect <pkg>")
                return
            }
            pkgPath := args[3]
            m, err := archive.ReadManifest(pkgPath)
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            fmt.Println(color.Bold("Package Manifest:"))
            t := tablewriter.NewTable(os.Stdout,
                tablewriter.WithRendition(tw.Rendition{
                    Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                    Symbols: tw.NewSymbols(tw.StyleRounded),
                    Settings: tw.Settings{
                        Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                        Lines:      tw.Lines{ShowHeaderLine: tw.On},
                    },
                }),
                tablewriter.WithHeader([]string{"FIELD", "VALUE"}),
                tablewriter.WithRowAlignment(tw.AlignLeft),
                tablewriter.WithHeaderAlignment(tw.AlignLeft),
            )
            t.Append([]string{"Package", m.PackageName})
            t.Append([]string{"Version", m.Version})
            t.Append([]string{"Payload Hash", m.PayloadHash})
            t.Append([]string{"SBOM Hash", m.SBOMHash})
            t.Append([]string{"Expires At", m.ExpiresAt})
            depStrs := make([]string, len(m.Dependencies))
            for i, d := range m.Dependencies {
                depStrs[i] = d.Name + "@" + d.Version
            }
            t.Append([]string{"Dependencies", strings.Join(depStrs, ", ")})
            t.Render()

        case "verify":
            if argc < 4 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox package verify <pkg>")
                return
            }
            pkgPath := args[3]
            s, a, err := openVerifiedDB()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            defer s.Close()
            defer a.Close()

            m, err := archive.ReadManifest(pkgPath)
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }

            sigPath := pkgPath + ".sig"
            allPassed, results := verifyPackage(s, pkgPath, sigPath, m)
            renderVerificationTable(results)

            if !allPassed {
                fmt.Println("  " + color.Fail("Status: verification failed"))
                return
            }
            fmt.Println("  " + color.Ok("Status: verification passed"))

        case "import":
            if argc < 4 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox package import <pkg>")
                return
            }
            pkgPath := args[3]
            s, a, err := openVerifiedDB()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            defer s.Close()
            defer a.Close()

            m, err := archive.ReadManifest(pkgPath)
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }

            sigPath := pkgPath + ".sig"
            allPassed, results := verifyPackage(s, pkgPath, sigPath, m)
            renderVerificationTable(results)

            if !allPassed {
                fmt.Println("  " + color.Fail("Status: import rejected"))
                a.WriteEvent("blackbox", "IMPORT_REJECTED", m.PackageName, m.Version, "failed", "verification failed", metaWithState(s, ""))
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
            auditID, _ := a.WriteEvent("blackbox", "PACKAGE_IMPORTED", m.PackageName, m.Version, "success", "", metaWithState(s, m.PayloadHash))
            fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

        case "install":
            if argc < 4 {
                fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox package install <pkg>  or  blackbox package install <name> --version <ver>")
                return
            }
            s, a, err := openVerifiedDB()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            defer s.Close()
            defer a.Close()

            if strings.HasSuffix(args[3], ".agpkg") {
                handleInstallPackage(s, a, args[3])
            } else {
                name := args[3]
                var version string
                for i := 4; i < argc; i++ {
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
                handleInstall(s, a, name, version)
            }

        default:
            fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown package subcommand:", sub)
            fmt.Println("  valid subcommands: create, sign, inspect, verify, import, install (<pkg> or <name> --version <ver>)")
        }

    case "trust":
        if argc < 3 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox trust add/list/remove")
            return
        }
        s, a, err := openVerifiedDB()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        defer a.Close()

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
            auditID, _ := a.WriteEvent("blackbox", "TRUST_ADDED", name, "", "success", "", metaWithState(s, ""))
            fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

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
            auditID, _ := a.WriteEvent("blackbox", "TRUST_REMOVED", name, "", "success", "", metaWithState(s, ""))
            fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

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
        s, a, err := openVerifiedDB()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        defer a.Close()

        m, err := archive.ReadManifest(pkgPath)
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }

        sigPath := pkgPath + ".sig"
        allPassed, results := verifyPackage(s, pkgPath, sigPath, m)
        renderVerificationTable(results)

        if !allPassed {
            fmt.Println("  " + color.Fail("Status: import rejected"))
            a.WriteEvent("blackbox", "IMPORT_REJECTED", m.PackageName, m.Version, "failed", "verification failed", metaWithState(s, ""))
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
        auditID, _ := a.WriteEvent("blackbox", "PACKAGE_IMPORTED", m.PackageName, m.Version, "success", "", metaWithState(s, m.PayloadHash))
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
        s, a, err := openVerifiedDB()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
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
        auditID, _ := a.WriteEvent("blackbox", "PACKAGE_APPROVED", name, version, "success", "", metaWithState(s, ""))
        fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

    case "install":
        if argc < 3 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox install <pkg>  or  blackbox install <name> --version <ver>")
            return
        }
        s, a, err := openVerifiedDB()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        defer a.Close()

        if strings.HasSuffix(args[2], ".agpkg") {
            handleInstallPackage(s, a, args[2])
        } else {
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
            handleInstall(s, a, name, version)
        }

    case "status":
        s, a, err := openVerifiedDB()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        defer a.Close()

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
        s, a, err := openVerifiedDB()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        defer s.Close()
        defer a.Close()

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
            auditID, _ := a.WriteEvent("blackbox", "POLICY_BLOCKED", pkg, ver, "success", reason, metaWithState(s, ""))
            fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

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
            auditID, _ := a.WriteEvent("blackbox", "POLICY_UNBLOCKED", pkg, ver, "success", "", metaWithState(s, ""))
            fmt.Println(color.Cyan("Audit:"), "AUDIT-"+auditID)

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
        if argc < 3 {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox audit verify-chain|log")
            return
        }
        switch args[2] {
        case "verify-chain":
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

        case "log":
            a, err := audit.Open(dbPath)
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            defer a.Close()
            events, err := a.ListEvents()
            if err != nil {
                fmt.Fprintln(os.Stderr, color.Red("error:"), err)
                return
            }
            if len(events) == 0 {
                fmt.Println("  (no audit events)")
            } else {
                fmt.Println(color.Bold("Audit log:"))
                t := tablewriter.NewTable(os.Stdout,
                    tablewriter.WithRendition(tw.Rendition{
                        Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.On, Bottom: tw.On},
                        Symbols: tw.NewSymbols(tw.StyleRounded),
                        Settings: tw.Settings{
                            Separators: tw.Separators{BetweenRows: tw.On, BetweenColumns: tw.On},
                            Lines:      tw.Lines{ShowHeaderLine: tw.On},
                        },
                    }),
                    tablewriter.WithHeader([]string{"ID", "TIMESTAMP", "ACTION", "PACKAGE", "VERSION", "RESULT"}),
                    tablewriter.WithRowAlignment(tw.AlignLeft),
                    tablewriter.WithHeaderAlignment(tw.AlignLeft),
                )
                for _, e := range events {
                    t.Append([]string{
                        fmt.Sprintf("%d", e.ID),
                        e.Timestamp,
                        e.Action,
                        e.PackageName,
                        e.Version,
                        e.Result,
                    })
                }
                t.Render()
            }

        default:
            fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown audit subcommand:", args[2])
        }

    case "db":
        if argc < 3 || args[2] != "verify" {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "usage: blackbox db verify")
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

        valid, count, err := a.VerifyChain()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), err)
            return
        }
        if valid {
            fmt.Println("Audit chain ", color.Ok("valid"))
        } else {
            fmt.Println("Audit chain ", color.Fail("TAMPERED"))
        }
        fmt.Println("Events      ", count)

        stateHash, err := s.HashState()
        if err != nil {
            fmt.Fprintln(os.Stderr, color.Red("error:"), "computing state hash:", err)
            return
        }
        fmt.Println("State hash  ", color.Cyan(stateHash))

        events, _ := a.ListEvents()
        if len(events) > 0 {
            lastMeta := events[0].Meta
            if lastMeta != "" {
                fmt.Println("Last event  ", events[0].Action, events[0].PackageName, events[0].Version)
                for _, p := range strings.Split(lastMeta, "|") {
                    if strings.HasPrefix(p, "state:") {
                        lastState := strings.TrimPrefix(p, "state:")
                        if lastState == stateHash {
                            fmt.Println("DB state    ", color.Ok("matches audit log"))
                        } else {
                            fmt.Println("DB state    ", color.Fail("MISMATCH - tables modified outside audit"))
                            fmt.Println("  recorded: ", lastState)
                            fmt.Println("  current:  ", stateHash)
                        }
                    }
                }
            }
        }

    default:
        fmt.Fprintln(os.Stderr, color.Red("error:"), "unknown command:", cmd)
        fmt.Println()
        printUsage()
    }
}
