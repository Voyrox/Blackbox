package archive

import (
    "archive/tar"
    "compress/gzip"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"
)

type Dependency struct {
    Name    string `json:"name"`
    Version string `json:"version"`
}

type Manifest struct {
    PackageName            string       `json:"package_name"`
    Version                string       `json:"version"`
    BuildID                string       `json:"build_id"`
    TargetOS               string       `json:"target_os"`
    TargetArch             string       `json:"target_arch"`
    PayloadHash            string       `json:"payload_hash"`
    SBOMHash               string       `json:"sbom_hash"`
    MinimumAllowedVersion  string       `json:"minimum_allowed_version"`
    RequiresReboot         bool         `json:"requires_reboot"`
    Dependencies           []Dependency `json:"dependencies"`
    CreatedBy              string       `json:"created_by"`
    ExpiresAt              string       `json:"expires_at"`
}

func CreatePackage(name, version, payloadPath, sbomPath, outputPath string) error {
    sbomHash, err := hashFile(sbomPath)
    if err != nil {
        return fmt.Errorf("hash sbom: %w", err)
    }

    payloadHash, err := hashDir(payloadPath)
    if err != nil {
        return fmt.Errorf("hash payload: %w", err)
    }

    m := Manifest{
        PackageName:           name,
        Version:               version,
        BuildID:               time.Now().UTC().Format("2006-01-02T15:04:05Z"),
        TargetOS:              "linux",
        TargetArch:            "x86_64",
        PayloadHash:           "sha256:" + payloadHash,
        SBOMHash:              "sha256:" + sbomHash,
        MinimumAllowedVersion: "0.0.0",
        RequiresReboot:        false,
        Dependencies:          []Dependency{},
        CreatedBy:             "blackbox",
        ExpiresAt:             time.Now().UTC().Add(90 * 24 * time.Hour).Format("2006-01-02T15:04:05Z"),
    }

    os.MkdirAll(filepath.Dir(outputPath), 0755)
    out, err := os.Create(outputPath)
    if err != nil {
        return fmt.Errorf("create output: %w", err)
    }
    defer out.Close()

    gw := gzip.NewWriter(out)
    defer gw.Close()
    tw := tar.NewWriter(gw)
    defer tw.Close()

    if err := addFileToTar(tw, sbomPath, "metadata/sbom.spdx.json"); err != nil {
        return fmt.Errorf("add sbom to archive: %w", err)
    }

    manifestJSON, err := json.MarshalIndent(m, "", "  ")
    if err != nil {
        return fmt.Errorf("marshal manifest: %w", err)
    }
    if err := addBytesToTar(tw, manifestJSON, "metadata/manifest.json", 0644); err != nil {
        return fmt.Errorf("add manifest to archive: %w", err)
    }

    if err := addDirToTar(tw, payloadPath, "payload"); err != nil {
        return fmt.Errorf("add payload to archive: %w", err)
    }

    return nil
}

func ReadManifest(pkgPath string) (*Manifest, error) {
    f, err := os.Open(pkgPath)
    if err != nil {
        return nil, fmt.Errorf("open package: %w", err)
    }
    defer f.Close()

    gr, err := gzip.NewReader(f)
    if err != nil {
        return nil, fmt.Errorf("gzip reader: %w", err)
    }
    defer gr.Close()

    tr := tar.NewReader(gr)
    for {
        hdr, err := tr.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, fmt.Errorf("tar read: %w", err)
        }
        if hdr.Name == "metadata/manifest.json" {
            var m Manifest
            if err := json.NewDecoder(tr).Decode(&m); err != nil {
                return nil, fmt.Errorf("decode manifest: %w", err)
            }
            return &m, nil
        }
    }
    return nil, fmt.Errorf("manifest not found in package")
}

func HashPayload(dir string) (string, error) {
    return hashDir(dir)
}

func readManifestFile(path string) (*Manifest, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var m Manifest
    if err := json.Unmarshal(data, &m); err != nil {
        return nil, err
    }
    return &m, nil
}

func hashFile(path string) (string, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return "", err
    }
    h := sha256.Sum256(data)
    return fmt.Sprintf("%x", h), nil
}

func hashDir(dir string) (string, error) {
    h := sha256.New()
    err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if fi.IsDir() {
            return nil
        }
        rel, err := filepath.Rel(dir, path)
        if err != nil {
            return err
        }
        h.Write([]byte(rel))
        data, err := os.ReadFile(path)
        if err != nil {
            return err
        }
        h.Write(data)
        return nil
    })
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func addFileToTar(tw *tar.Writer, srcPath, tarPath string) error {
    data, err := os.ReadFile(srcPath)
    if err != nil {
        return err
    }
    return addBytesToTar(tw, data, tarPath, 0644)
}

func addBytesToTar(tw *tar.Writer, data []byte, tarPath string, mode int64) error {
    hdr := &tar.Header{
        Name:     tarPath,
        Size:     int64(len(data)),
        Mode:     mode,
        Typeflag: tar.TypeReg,
    }
    if err := tw.WriteHeader(hdr); err != nil {
        return err
    }
    _, err := tw.Write(data)
    return err
}

func addDirToTar(tw *tar.Writer, srcDir, tarBase string) error {
    return filepath.Walk(srcDir, func(path string, fi os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        rel, err := filepath.Rel(srcDir, path)
        if err != nil {
            return err
        }
        tarName := filepath.ToSlash(filepath.Join(tarBase, rel))

        if fi.IsDir() {
            hdr := &tar.Header{
                Name:     tarName + "/",
                Mode:     0755,
                Typeflag: tar.TypeDir,
            }
            if err := tw.WriteHeader(hdr); err != nil {
                return err
            }
            return nil
        }

        data, err := os.ReadFile(path)
        if err != nil {
            return err
        }
        return addBytesToTar(tw, data, tarName, 0644)
    })
}

func VersionLessThan(a, b string) bool {
    if a == b {
        return false
    }
    if a == "" || b == "" {
        return a < b
    }
    pa := strings.Split(a, ".")
    pb := strings.Split(b, ".")
    maxLen := len(pa)
    if len(pb) > maxLen {
        maxLen = len(pb)
    }
    for i := 0; i < maxLen; i++ {
        var va, vb int
        if i < len(pa) {
            fmt.Sscanf(pa[i], "%d", &va)
        }
        if i < len(pb) {
            fmt.Sscanf(pb[i], "%d", &vb)
        }
        if va != vb {
            return va < vb
        }
    }
    return false
}

func ISO8601Now() string {
    return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}
