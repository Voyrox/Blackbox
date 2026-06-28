package crypto

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
)

func GenerateKeypair(privPath, pubPath string) error {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return fmt.Errorf("key generation: %w", err)
    }

    privDER, err := x509.MarshalECPrivateKey(key)
    if err != nil {
        return fmt.Errorf("marshal private key: %w", err)
    }
    privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
    if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
        return fmt.Errorf("write private key: %w", err)
    }

    pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
    if err != nil {
        return fmt.Errorf("marshal public key: %w", err)
    }
    pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
    if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
        return fmt.Errorf("write public key: %w", err)
    }

    return nil
}

func SignFile(filePath, keyPath, sigPath string) error {
    keyPEM, err := os.ReadFile(keyPath)
    if err != nil {
        return fmt.Errorf("read private key: %w", err)
    }
    block, _ := pem.Decode(keyPEM)
    if block == nil {
        return fmt.Errorf("no PEM block in private key")
    }
    key, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("parse private key: %w", err)
    }

    data, err := os.ReadFile(filePath)
    if err != nil {
        return fmt.Errorf("read file: %w", err)
    }
    hash := sha256.Sum256(data)
    sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
    if err != nil {
        return fmt.Errorf("sign: %w", err)
    }
    if err := os.WriteFile(sigPath, sig, 0644); err != nil {
        return fmt.Errorf("write signature: %w", err)
    }
    return nil
}

func verify(data []byte, sig []byte, pubKeyPEM string) (bool, error) {
    block, _ := pem.Decode([]byte(pubKeyPEM))
    if block == nil {
        return false, fmt.Errorf("no PEM block in public key")
    }
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return false, fmt.Errorf("parse public key: %w", err)
    }
    ecdsaPub, ok := pub.(*ecdsa.PublicKey)
    if !ok {
        return false, fmt.Errorf("not an ECDSA public key")
    }
    hash := sha256.Sum256(data)
    return ecdsa.VerifyASN1(ecdsaPub, hash[:], sig), nil
}

func VerifyFile(filePath, sigPath, pubKeyPath string) (bool, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return false, fmt.Errorf("read file: %w", err)
    }
    sig, err := os.ReadFile(sigPath)
    if err != nil {
        return false, fmt.Errorf("read signature: %w", err)
    }
    pubPEM, err := os.ReadFile(pubKeyPath)
    if err != nil {
        return false, fmt.Errorf("read public key: %w", err)
    }
    return verify(data, sig, string(pubPEM))
}

func VerifyFileWithKey(filePath, sigPath, pubKeyPEM string) (bool, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return false, fmt.Errorf("read file: %w", err)
    }
    sig, err := os.ReadFile(sigPath)
    if err != nil {
        return false, fmt.Errorf("read signature: %w", err)
    }
    return verify(data, sig, pubKeyPEM)
}

func SHA256File(path string) (string, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return "", err
    }
    h := sha256.Sum256(data)
    return fmt.Sprintf("%x", h), nil
}

func SHA256Data(data string) string {
    h := sha256.Sum256([]byte(data))
    return fmt.Sprintf("%x", h)
}
