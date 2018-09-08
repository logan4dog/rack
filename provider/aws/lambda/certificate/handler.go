package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
)

var (
	ACM = acm.New(session.New(), nil)
)

type Request struct {
	LogicalResourceId  string
	PhysicalResourceId string
	RequestId          string
	RequestType        string
	ResourceProperties map[string]interface{}
	ResourceType       string
	ResponseURL        string
	StackId            string
}

type Response struct {
	Data               map[string]string
	LogicalResourceId  string
	PhysicalResourceId string
	Reason             string
	RequestId          string
	Status             string
	StackId            string
}

func main() {
	lambda.Start(Handler)
}

func Handler(request Request) error {
	fmt.Printf("request = %+v\n", request)

	switch request.RequestType {
	case "Create", "Update":
		if err := Create(request); err != nil {
			respondError(request, err)
		}
	case "Delete":
		if err := Delete(request); err != nil {
			respondError(request, err)
		}
	default:
		respondError(request, fmt.Errorf("unknown RequestType: %s", request.RequestType))
	}

	return nil
}

func Create(request Request) error {
	domain, ok := request.ResourceProperties["Domain"].(string)
	if !ok {
		return fmt.Errorf("invalid Domain")
	}

	pub, key, err := generateSelfSignedCertificate(domain)
	if err != nil {
		return fmt.Errorf("could not generate self-signed certificate for: %s", domain)
	}

	res, err := ACM.ImportCertificate(&acm.ImportCertificateInput{
		Certificate: pub,
		PrivateKey:  key,
	})
	if err != nil {
		return err
	}
	if res.CertificateArn == nil {
		return fmt.Errorf("invalid certificate arn")
	}

	response := Response{
		LogicalResourceId:  request.LogicalResourceId,
		PhysicalResourceId: *res.CertificateArn,
		RequestId:          request.RequestId,
		Status:             "SUCCESS",
		StackId:            request.StackId,
	}

	return respond(request.ResponseURL, response)
}

func Delete(request Request) error {
	_, err := ACM.DeleteCertificate(&acm.DeleteCertificateInput{
		CertificateArn: aws.String(request.PhysicalResourceId),
	})
	if err != nil {
		return err
	}

	response := Response{
		LogicalResourceId:  request.LogicalResourceId,
		PhysicalResourceId: request.PhysicalResourceId,
		RequestId:          request.RequestId,
		Status:             "SUCCESS",
		StackId:            request.StackId,
	}

	return respond(request.ResponseURL, response)
}

func generateSelfSignedCertificate(host string) ([]byte, []byte, error) {
	rkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Convox"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	data, err := x509.CreateCertificate(rand.Reader, &template, &template, &rkey.PublicKey, rkey)
	if err != nil {
		return nil, nil, err
	}

	pub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rkey)})

	return pub, key, nil
}

func respond(url string, response Response) error {
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func respondError(request Request, err error) error {
	response := Response{
		LogicalResourceId:  request.LogicalResourceId,
		PhysicalResourceId: request.PhysicalResourceId,
		Reason:             err.Error(),
		RequestId:          request.RequestId,
		Status:             "FAILED",
		StackId:            request.StackId,
	}

	return respond(request.ResponseURL, response)
}
