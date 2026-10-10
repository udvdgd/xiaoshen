// 小神算法 · 桌面版 xshenctl (纯 Go 标准库, 静态跨平台)
// enc/dec/obf/info; XSD1=自研异或外层+AES-256-GCM(PBKDF2 40万), XSO1=自研流混淆
package main

import (
	"crypto/aes"
	crand "crypto/rand"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)
	var bi [4]byte
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(bi[:], uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(salt); mac.Write(bi[:])
		U := mac.Sum(nil)
		T := make([]byte, hLen); copy(T, U)
		for n := 1; n < iter; n++ {
			mac = hmac.New(sha256.New, password); mac.Write(U); U = mac.Sum(nil)
			for i := 0; i < hLen; i++ { T[i] ^= U[i] }
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}

type xsStream struct {
	s   [256]byte
	a   int
	acc uint64
}

func newXsStream(key []byte) *xsStream {
	seed := pbkdf2(key, []byte("xshen::outer-v1"), 12000, 256)
	x := &xsStream{}
	for i := 0; i < 256; i++ { x.s[i] = byte(i) }
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(x.s[i]) + int(seed[i]) + i*31) & 0xFF
		x.s[i], x.s[j] = x.s[j], x.s[i]
	}
	x.acc = binary.LittleEndian.Uint64(seed[:8]) ^ binary.LittleEndian.Uint64(seed[8:16])
	if x.acc == 0 { x.acc = 0x9E3779B97F4A7C15 }
	return x
}

func rotl64(v uint64, n uint) uint64 { return (v << n) | (v >> (64 - n)) }

func (x *xsStream) next(n int) byte {
	x.a = (x.a + 1) & 0xFF
	lo := byte((x.acc >> uint(n&31)) & 0xFF)
	b := (int(x.s[x.a]) + int(lo) + n) & 0xFF
	x.s[x.a], x.s[b] = x.s[b], x.s[x.a]
	t := x.s[(int(x.s[x.a])+int(x.s[b]))&0xFF]
	x.acc = (rotl64(x.acc^(uint64(t)*0x9E3779B185EBCA87), uint((17+(n&7))&63)) + uint64(n+1)*0x100000001B3)
	return t ^ byte(x.acc&0xFF) ^ byte((x.acc>>23)&0xFF) ^ byte((x.acc>>40)&0xFF)
}

func xsCrypt(data, key []byte) []byte {
	x := newXsStream(key)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i++ { out[i] = data[i] ^ x.next(i) }
	return out
}

func gcmSeal(data, key []byte) ([]byte, error) {
	salt := randBytes(16); nonce := randBytes(12)
	dk := pbkdf2(key, salt, 400000, 32)
	block, err := aes.NewCipher(dk)
	if err != nil { return nil, err }
	g, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	ct := g.Seal(nil, nonce, data, nil)
	return append(append(salt, nonce...), ct...), nil
}

func gcmOpen(blob, key []byte) ([]byte, error) {
	if len(blob) < 28 { return nil, errors.New("too short") }
	salt, nonce, ct := blob[:16], blob[16:28], blob[28:]
	dk := pbkdf2(key, salt, 400000, 32)
	block, err := aes.NewCipher(dk)
	if err != nil { return nil, err }
	g, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	return g.Open(nil, nonce, ct, nil)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		var v uint64 = uint64(n) * 0x9E3779B97F4A7C15
		for i := range b { v = v*6364136223846793005 + 1442695040888963407; b[i] = byte(v >> 33) }
	}
	return b
}

func encryptStrong(data, key []byte) ([]byte, error) {
	inner, err := gcmSeal(data, key)
	if err != nil { return nil, err }
	return append([]byte("XSD1"), xsCrypt(inner, key)...), nil
}
func decryptStrong(blob, key []byte) ([]byte, error) {
	if len(blob) < 4 || string(blob[:4]) != "XSD1" { return nil, errors.New("not XSD1") }
	return gcmOpen(xsCrypt(blob[4:], key), key)
}
func encryptObf(data, key []byte) []byte { return append([]byte("XSO1"), xsCrypt(data, key)...) }
func decryptObf(blob, key []byte) []byte { return xsCrypt(blob[4:], key) }

var scriptExts = map[string]bool{".lua": true, ".js": true, ".py": true, ".ts": true, ".sh": true, ".txt": true, ".json": true}

func processFile(path string, key []byte, enc bool) error {
	data, err := os.ReadFile(path)
	if err != nil { return err }
	if enc {
		out, err := encryptStrong(data, key)
		if err != nil { return err }
		dst := path + ".xsn"
		if err := os.WriteFile(dst, out, 0644); err != nil { return err }
		fmt.Printf("[+] 加密 %s -> %s (%d 字节)\n", filepath.Base(path), filepath.Base(dst), len(out))
	} else {
		var pt []byte
		magic := string(data[:min(4, len(data))])
		switch magic {
		case "XSD1":
			pt, err = decryptStrong(data, key)
		case "XSO1":
			pt = decryptObf(data, key)
		default:
			return fmt.Errorf("未识别容器 %q", magic)
		}
		if err != nil { return fmt.Errorf("解密失败(密钥错误或损坏): %w", err) }
		base := strings.TrimSuffix(path, filepath.Ext(path))
		dst := base + ".plain" + filepath.Ext(base)
		if err := os.WriteFile(dst, pt, 0644); err != nil { return err }
		fmt.Printf("[+] 解密 %s -> %s (%d 字节)\n", filepath.Base(path), filepath.Base(dst), len(pt))
	}
	return nil
}

func isContainer(p string) bool {
	b, err := os.ReadFile(p)
	if err != nil || len(b) < 4 { return false }
	m := string(b[:4])
	return m == "XSD1" || m == "XSO1" || m == "XSN1" || m == "XSN2"
}

func walk(root string, key []byte, enc bool) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() { return nil }
		ext := strings.ToLower(filepath.Ext(p))
		if enc {
			if scriptExts[ext] {
				if e := processFile(p, key, true); e != nil { fmt.Println("  [!]", e) }
			}
		} else if ext == ".xsn" || isContainer(p) {
			if e := processFile(p, key, false); e != nil { fmt.Println("  [!]", e) }
		}
		return nil
	})
}

func info(path string) {
	data, err := os.ReadFile(path)
	if err != nil { fmt.Println("[!]", err); return }
	fmt.Printf("文件 %s\n大小 %d\n魔数 %q\n", filepath.Base(path), len(data), data[:min(4, len(data))])
}

func min(a, b int) int { if a < b { return a }; return b }

func main() {
	if len(os.Args) < 3 { printUsage(); return }
	cmd, target := os.Args[1], os.Args[2]
	key := []byte("default-xshen-key")
	if len(os.Args) >= 4 { key = []byte(os.Args[3]) }
	fi, err := os.Stat(target)
	if err != nil { fmt.Println("[!]", err); return }
	switch cmd {
	case "enc":
		if fi.IsDir() { walk(target, key, true) } else {
			if e := processFile(target, key, true); e != nil { fmt.Println("[!]", e) }
		}
	case "dec":
		if fi.IsDir() { walk(target, key, false) } else {
			if e := processFile(target, key, false); e != nil { fmt.Println("[!]", e) }
		}
	case "obf":
		data, _ := os.ReadFile(target)
		os.WriteFile(target+".obf", encryptObf(data, key), 0644)
		fmt.Println("[+] 自研混淆完成")
	case "info":
		info(target)
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`小神算法 桌面版 xshenctl:
  xshenctl enc <文件|目录> [密钥]
  xshenctl dec <文件|目录> [密钥]
  xshenctl obf <文件> [密钥]
  xshenctl info <文件>`)
}
