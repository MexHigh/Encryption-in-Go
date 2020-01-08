package rsa

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
)

// KeyPair represents an key pair
type KeyPair struct {
	Pub  PublicKey
	Priv PrivateKey
}

// PublicKey represents the public part of a key pair
type PublicKey struct {
	e, n int
}

// PrivateKey represents the private part of a key pair
type PrivateKey struct {
	d, n int
}

// NewKeyPair generates and returns a rsaKeyPair
func NewKeyPair(p, q int) (KeyPair, error) {

	n := p * q
	phiN := (p - 1) * (q - 1)

	// e suchen kleiner phiN und teilerfremd
	e, err := generateE(phiN)
	if err != nil {
		return KeyPair{}, err
	}
	pub := PublicKey{e, n}

	d, err := generateD(e, phiN)
	if err != nil {
		return KeyPair{}, err
	}
	priv := PrivateKey{d, n}

	return KeyPair{pub, priv}, nil
}

// SaveKeyPair saves the key pair to the current directory in base64 format
func SaveKeyPair(kp KeyPair) error {

	// public key
	publicString := strconv.Itoa(kp.Pub.e) + "-" + strconv.Itoa(kp.Pub.n)
	publicStringBase64 := "-----BEGIN RSA PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString([]byte(publicString)) + "\n-----END RSA PUBLIC KEY-----"
	fOwnPub, err := os.Create("./ownpub.key")
	if err != nil {
		return err
	}
	defer fOwnPub.Close()
	fOwnPub.Write([]byte(publicStringBase64))

	// private key
	privateString := strconv.Itoa(kp.Priv.d) + "-" + strconv.Itoa(kp.Priv.n)
	privateStringBase64 := "-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte(privateString)) + "\n-----END RSA PRIVATE KEY-----"
	fOwnPriv, err := os.Create("./ownpriv.key")
	if err != nil {
		return err
	}
	defer fOwnPriv.Close()
	fOwnPriv.Write([]byte(privateStringBase64))

	return nil
}

// LoadOwnKeyPair loads the base64 encoded key pair from the current directory
func LoadOwnKeyPair() (KeyPair, error) { // TODO muss irgendwie einfacher gehen (eine methode mit filename als input)

	// public key
	fPublicKey, err := os.Open("ownpub.key")
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	defer fPublicKey.Close()
	scanner := bufio.NewScanner(fPublicKey)
	var publicKeyBase64 string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "-----") {
			publicKeyBase64 += strings.ReplaceAll(line, "\n", "")
		}
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	publicKeyArr := strings.Split(string(publicKey), "-")
	e, err := strconv.Atoi(publicKeyArr[0])
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	n, err := strconv.Atoi(publicKeyArr[1])
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	pubKey := PublicKey{e, n}

	// private key
	fPrivateKey, err := os.Open("ownpriv.key")
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	defer fPrivateKey.Close()
	scanner = bufio.NewScanner(fPrivateKey)
	var privateKeyBase64 string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "-----") {
			privateKeyBase64 += strings.ReplaceAll(line, "\n", "")
		}
	}
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	privateKeyArr := strings.Split(string(privateKey), "-")
	d, err := strconv.Atoi(privateKeyArr[0])
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	n, err = strconv.Atoi(privateKeyArr[1])
	if err != nil {
		return KeyPair{PublicKey{}, PrivateKey{}}, err
	}
	privKey := PrivateKey{d, n}

	return KeyPair{pubKey, privKey}, nil
}

// LoadPartnerPubKey loads the base64 encoded public key of the communication partner
func LoadPartnerPubKey() (PublicKey, error) { // TODO return all errors

	// public key
	fPublicKey, err := os.Open("partnerpub.key")
	if err != nil {
		return PublicKey{}, err
	}
	defer fPublicKey.Close()
	scanner := bufio.NewScanner(fPublicKey)
	var publicKeyBase64 string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "-----") {
			publicKeyBase64 += strings.ReplaceAll(line, "\n", "")
		}
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return PublicKey{}, err
	}
	publicKeyArr := strings.Split(string(publicKey), "-")
	e, err := strconv.Atoi(publicKeyArr[0])
	if err != nil {
		return PublicKey{}, err
	}
	n, err := strconv.Atoi(publicKeyArr[1])
	if err != nil {
		return PublicKey{}, err
	}
	pubKey := PublicKey{e, n}

	return pubKey, nil
}

// SendPublicKey sends the public key over a socket connection (NOT IMPLEMENTED YET)
func SendPublicKey(conn *net.Conn) error {
	content, err := ioutil.ReadFile("ownpub.key")
	if err != nil {
		return err
	}
	(*conn).Write(content)
	return errors.New("rsa.go: Error while sending public key")
}

// ReceivePublicKey uses a connection to receive one public key sent from another person via SendPublicKey
func ReceivePublicKey(conn *net.Conn) error {
	rcvd, err := bufio.NewReader(*conn).ReadString('\n')
	if err != nil {
		return err
	}
	file, err := os.Create("partnerpub.key")
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(rcvd)
	if err != nil {
		return err
	}
	return nil
}

// RandomPrime generates a random prime with b bits
func RandomPrime(b int) int {
	prime, err := rand.Prime(rand.Reader, b) // 10 bit RSA --> insecure
	if err != nil {
		log.Fatal(err)
	}
	return int((*prime).Int64())
}

func generateE(phiN int) (int, error) {
	for i := 3; i < phiN; i += 2 {
		if ggT(phiN, i) == 1 {
			return i, nil
		}
	}
	return 0, errors.New("rsa.go: Error generating e parameter")
}

func generateD(e, phiN int) (int, error) {
	eeA := eeA(phiN, e, 1)
	if eeA < 0 {
		return eeA + phiN, nil
	}
	return eeA, nil
}

func ggT(a, b int) int {
	if a%b == 0 {
		return b
	}
	return ggT(b, a%b)
}

func eeA(a, b, ggT int) int {
	if a%b == 0 {
		return 1
	}
	return (ggT - a*eeA(b, a%b, ggT)) / b
}

func squareAndMultiply(base, exp, mod int) int {
	expBin := strconv.FormatInt(int64(exp), 2)
	expBinArr := []rune(expBin)
	return squareAndMultiplyRec(base, expBinArr, 0, mod, 1)
}

func squareAndMultiplyRec(base int, expBin []rune, expBinIndex, mod, result int) int {
	if len(expBin) == expBinIndex {
		return result % mod
	}
	if expBin[expBinIndex] == '1' {
		result = int(math.Pow(float64(result), 2)) % mod
		result = (result * base) % mod
		return squareAndMultiplyRec(base, expBin, expBinIndex+1, mod, result)
	} // else
	result = int(math.Pow(float64(result), 2)) % mod
	return squareAndMultiplyRec(base, expBin, expBinIndex+1, mod, result)
}

// Encrypt encrypts a string with the help of the partners public key
func (partnerPub PublicKey) Encrypt(cleartext string) string {
	var ciphertext string
	for i, r := range cleartext {
		rEnc := squareAndMultiply(int(r), partnerPub.e, partnerPub.n)
		ciphertext += strconv.Itoa(rEnc)
		if i != len(cleartext)-1 {
			ciphertext += "-"
		}
	}
	return ciphertext + "\n"
}

// Decrypt decrypts an encoded string with the help of the own private key
func (myPriv PrivateKey) Decrypt(ciphertext string) string {
	cleartext := ""
	ciphertextArr := strings.Split(ciphertext, "-")
	for _, cypherrune := range ciphertextArr {
		cypherruneInt, _ := strconv.Atoi(cypherrune)
		runeDec := squareAndMultiply(cypherruneInt, myPriv.d, myPriv.n)
		//fmt.Println("Received:", cypherrune) //
		//fmt.Println("Decoded to:", runeDec)  //
		cleartext += string(runeDec)
	}
	return cleartext
}
