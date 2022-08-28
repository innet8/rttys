package xrsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
)

const (
	RsaAlgorithmSign = crypto.SHA256
)

type XRsa struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// CreateKeys 创建对象
func CreateKeys(publicKeyWriter, privateKeyWriter io.Writer, keyLength int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}
	derStream, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derStream,
	}
	err = pem.Encode(privateKeyWriter, block)
	if err != nil {
		return err
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	err = pem.Encode(publicKeyWriter, block)
	if err != nil {
		return err
	}

	return nil
}

// NewXRsa 创建对象
func NewXRsa(publicKey []byte, privateKey []byte) (*XRsa, error) {
	var pub *rsa.PublicKey
	var pri *rsa.PrivateKey
	if publicKey != nil {
		block, _ := pem.Decode(publicKey)
		if block == nil {
			return nil, errors.New("public key error")
		}
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub = pubInterface.(*rsa.PublicKey)
	}
	if privateKey != nil {
		block, _ := pem.Decode(privateKey)
		if block == nil {
			return nil, errors.New("private key error")
		}
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		pri, ok = priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key not supported")
		}
	}
	return &XRsa{
		publicKey:  pub,
		privateKey: pri,
	}, nil
}

// Encrypt 加密
func Encrypt(data, publicKey string) string {
	xrsb, err := NewXRsa([]byte(publicKey), nil)
	if err != nil {
		return ""
	}
	encrypted, err := xrsb.PublicEncrypt(data)
	if err != nil {
		return ""
	}
	return encrypted
}

// Decrypt 解密
func Decrypt(encrypted, publicKey string, privateKey string) string {
	xrsb, err := NewXRsa([]byte(publicKey), []byte(privateKey))
	if err != nil {
		return ""
	}
	decrypted, _ := xrsb.PrivateDecrypt(encrypted)
	if err != nil {
		return ""
	}
	return decrypted
}

// PublicEncrypt 公钥加密
func (r *XRsa) PublicEncrypt(data string) (string, error) {
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bts)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// PrivateDecrypt 私钥解密（必须有公私钥）
func (r *XRsa) PrivateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split(raw, partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

// PrivateEncrypt 私钥加密（必须有公私钥）
func (r *XRsa) PrivateEncrypt(data string) (string, error) {
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := PrivateEncrypt(r.privateKey, chunk)
		if err != nil {
			return "", err
		}

		buffer.Write(bts)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// PublicDecrypt 公钥解密
func (r *XRsa) PublicDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split(raw, partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := PublicDecrypt(r.publicKey, chunk)

		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

// Sign 签名
func (r *XRsa) Sign(data string) (string, error) {
	h := RsaAlgorithmSign.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, RsaAlgorithmSign, hashed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sign), err
}

// Verify 验证签名
func (r *XRsa) Verify(data string, sign string) error {
	h := RsaAlgorithmSign.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(r.publicKey, RsaAlgorithmSign, hashed, decodedSign)
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
