package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// そのまま実行するとエラーになるので、下記環境変数を設定すること
// export LANG=ja_JP.UTF-8
func main() {

	if len(os.Args) < 2 {
		log.Fatal("Usage: certviewer <certificate_file>")
	}

	//certs, err := loadCertificates(os.Args[1])
	cert, err := loadCertificate(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}
	
	// アプリ作成
	a := app.New()

	// ウィンドウ作成
	w := a.NewWindow("Certificate Viewer")

	// 階層データを構築
	data := map[string][]string{
		"": {"Subject", "Issuer", "Validity"},
		"Subject": {
			"CommonName: " + cert.Subject.CommonName,
			"Organization: " + sliceFirst(cert.Subject.Organization),
			"Country: " + sliceFirst(cert.Subject.Country),
		},
			"Issuer": {
			"CommonName: " + cert.Issuer.CommonName,
			"Organization: " + sliceFirst(cert.Issuer.Organization),
			"Country: " + sliceFirst(cert.Issuer.Country),
		},
		"Validity": {
			"NotBefore: " + cert.NotBefore.String(),
			"NotAfter: " + cert.NotAfter.String(),
		},
	}
	// ノード名→値の対応表
	nodeValues := map[string]string{
		"Version":      fmt.Sprintf("%d", cert.Version),
		"SerialNumber": cert.SerialNumber.String(),
		"Signature":    cert.PublicKeyAlgorithm.String(),
		"S-CommonName":   cert.Subject.CommonName,
		"S-Organization": fmt.Sprintf("%v", cert.Subject.Organization),
		"S-Country":      fmt.Sprintf("%v", cert.Subject.Country),
		"I-CommonName":   cert.Issuer.CommonName,
		"I-Organization": fmt.Sprintf("%v", cert.Issuer.Organization),
		"I-Country":      fmt.Sprintf("%v", cert.Issuer.Country),
		"notBefore":    cert.NotBefore.String(),
		"notAfter":     cert.NotAfter.String(),
		"algorithm":     cert.SignatureAlgorithm.String(),
		"signatureValue": fmt.Sprintf("%X", cert.Signature[:10]) + "...", // 長いので一部だけ
	}
	
	data2 := certToMap(cert)
	fmt.Println(data)
	fmt.Println(data2)
	fmt.Printf("Issuer CommonName = '%s'\n", cert.Issuer.CommonName)


	tree := widget.NewTree(
		//func(uid string) []string { return data[uid] }, // 子要素
		func(uid string) []string { return getChildNode(uid) }, // 子要素
		func(uid string) bool { return len(getChildNode(uid)) > 0 }, // 展開可能か
		func(branch bool) fyne.CanvasObject { // 各ノードのUI
			return widget.NewLabel("template")
		},
		func(uid string, branch bool, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			if val, ok := nodeValues[uid]; ok {
				label.SetText(fmt.Sprintf("%s: %s", uid, val))
			} else {
				label.SetText(uid)
			}
		},
	)

	// ラベルを配置
	//w.SetContent(widget.NewLabel(cert.Subject.Organization[0]))
	w.SetContent(container.NewStack(tree))
	w.Resize(fyne.NewSize(600, 400))

	// ウィンドウ表示
	w.ShowAndRun()
}

func sliceFirst(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
func certToMap(cert *x509.Certificate) map[string]interface{} {
	return map[string]interface{}{
		"TBSCertificate": map[string]interface{}{
			"Version": cert.Version,
			"SerialNumber": cert.SerialNumber,
			"Signature": cert.SignatureAlgorithm,
			"Issuer": map[string]interface{}{
				"I-CommonName": cert.Issuer.CommonName,
				"I-Organization": cert.Issuer.Organization,
				"I-Country": cert.Issuer.Country,
			},
			"Validity": map[string]interface{}{
				"notBefore": cert.NotBefore,
				"notAfter": cert.NotAfter,
			},
			"Subject": map[string]interface{}{
				"S-CommonName": cert.Subject.CommonName,
				"S-Organization": cert.Subject.Organization,
				"S-Country": cert.Subject.Country,
			},
		},
		"AlgorithmIdentifier": map[string]interface{}{
			"algorithm": cert.SignatureAlgorithm,
		},
		"signatureValue": cert.Signature,
	}
}

func getChildNode(id widget.TreeNodeID) []widget.TreeNodeID {
	switch id {
	case "":
		return []widget.TreeNodeID{"TBSCertificate", "AlgorithmIdentifier", "signatureValue"}
	case "TBSCertificate":
		return []widget.TreeNodeID{"Version", "SerialNumber","Signature","Issuer","Validity","Subject"}
	case "Issuer":
		return []widget.TreeNodeID{"I-CommonName", "I-Organization", "I-Country"}
	case "Subject":
		return []widget.TreeNodeID{"S-CommonName", "S-Organization", "S-Country"}
	case "Validity":
		return []widget.TreeNodeID{"notBefore", "notAfter"}
	case "AlgorithmIdentifier":
		return []widget.TreeNodeID{"algorithm"}
	}
	return []string{}
}

func loadCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

		var block *pem.Block
		block, data = pem.Decode(data)

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

	return cert, nil
}
