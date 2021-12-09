package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/google/trillian-examples/formats/log"
	"github.com/google/trillian-examples/serverless/client"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

const (
	logURL    = "https://qa.fwupd.org/ftlog/lvfsqa/"
	logPubKey = "lvfsqa+c463f084+AbAFMnhYEhBWzVlO0eGRA6KtPP3FCWpdg/FRRPMIlys6"
	logOrigin = "lvfsqa"

	zipName = "at90key123-FINAL.zip"
	thing   = "at90usbkey123.hex"

	// deviceCheckpointRaw what we'll pretend is the latest on-device checkpoint.
	deviceCheckpointRaw = "lvfsqa\n4\nKdF0yX/GfFEPKXB1+v0pnT0lxdvquyYRybl5/HhmgWk=\n\n— lvfsqa xGPwhE1lSYI9j14ckjbUMmPII56Niamhq+x3IpeeEPMiYU6x+iGDXUkvorVzvK9sOY6zeQYZhr91qAkqprEaJaZpWQw=\n"
)

var (
	logSigV = mustNewVerifier(logPubKey)
)

type manifest struct {
	ComponentID      int64    `json:"component_id"`
	GUIDs            []string `json:"guids"`
	FilenameContents string   `json:"filename_contents"`
	// TODO: probably should store this as base64 to be JSON-native
	SHA256Hex string `json:"sha256"`
	SHA256    []byte
}

func main() {
	flag.Parse()

	ctx := context.Background()
	f := mustCreateFetcher(logURL)
	hasher := rfc6962.DefaultHasher

	// User-space client
	glog.Info("In the user-space client...")

	z := mustOpenZip(zipName)

	glog.Info("Gathering artefacts from zip file...")
	// Load from zip: checkpoint, inc proof, manifest, firmware
	cpRaw := mustRead(z, fmt.Sprintf("%s.btcheckpoint", thing))
	cp := mustOpenCP(cpRaw, logOrigin, logSigV)
	incProof := mustReadIncProof(z, fmt.Sprintf("%s.btinclusionproof", thing))
	manifestRaw := mustRead(z, fmt.Sprintf("%s.btmanifest", thing))
	fw := mustRead(z, thing)

	// Ask the daemon for it's latest "golden" checkpoint:
	deviceCPSize := privGoldenCPSize()
	glog.Infof("Determine device golden checkpoint size: %d", deviceCPSize)

	// And use it to build a consistency proof by fetching log tiles:
	glog.Info("Build consistency proof between device CP and update CP")
	var consProof [][]byte
	if deviceCPSize < cp.Size {
		pb, err := client.NewProofBuilder(ctx, *cp, hasher.HashChildren, f)
		if err != nil {
			glog.Exitf("Failed to create proof builder: %v", err)
		}
		consProof, err = pb.ConsistencyProof(ctx, deviceCPSize, cp.Size)
		if err != nil {
			glog.Exitf("Failed to construct consistency proof between %d and %d", deviceCPSize, cp.Size)
		}
	} else {
		glog.Infof("Device CP not present or not smaller than new CP (%d)", deviceCPSize, cp.Size)
	}

	// TODO: whoops - we need to bundle the leaf index in the inclusion proof file too.
	// We'll just fetch it online for now:
	leafHash := hasher.HashLeaf(manifestRaw)
	leafIdx, err := client.LookupIndex(ctx, f, leafHash)
	if err != nil {
		glog.Exitf("Failed to look up leaf index: %v", err)
	}

	glog.Info("User-space done, sending RPC to priviledged daemon now")
	// Make like we're passing everything to the privileged daemon here:
	privRPC(fw, manifestRaw, cpRaw, incProof, leafIdx, consProof)

}

func privGoldenCPSize() uint64 {
	deviceCP := mustOpenCP([]byte(deviceCheckpointRaw), logOrigin, logSigV)
	return deviceCP.Size
}

func privRPC(fw []byte, manifestRaw []byte, cpRaw []byte, incProof [][]byte, leafIdx uint64, consProof [][]byte) {
	glog.Info("In priveledged daemon, all off-line now.")
	hasher := rfc6962.DefaultHasher
	logVerifier := merkle.NewLogVerifier(hasher)

	// TODO: verify signature on manifest
	mf := mustParseManifest(manifestRaw)

	fwHash := sha256.Sum256(fw)

	// verify f/w is committed to by manifest
	if got, want := fwHash[:], mf.SHA256; !bytes.Equal(got, want) {
		glog.Exitf("Got f/w hash %x, expected %x", got, want)
	}

	cp := mustOpenCP(cpRaw, logOrigin, logSigV)
	leafHash := hasher.HashLeaf(manifestRaw)
	// Verify that manifest is in the log
	if err := logVerifier.VerifyInclusionProof(int64(leafIdx), int64(cp.Size), incProof, cp.Hash, leafHash); err != nil {
		glog.Exitf("Invalid inclusion proof: %v", err)
	}

	deviceCP := mustOpenCP([]byte(deviceCheckpointRaw), logOrigin, logSigV)
	// Verify that new checkpoint is consistent with device "golden" checkpoint
	if err := logVerifier.VerifyConsistencyProof(int64(deviceCP.Size), int64(cp.Size), deviceCP.Hash, cp.Hash, consProof); err != nil {
		glog.Exitf("Invalid consistency proof: %v", err)
	}

	// Everything is good, we can proceed.
	// Update device's "golden" checkpoint:
	glog.Infof("Would store updated checkpoint:\n%s", cpRaw)

	// Install f/w
	glog.Info("Would flash firmware now.")

}

func mustCreateFetcher(baseURL string) client.Fetcher {
	u, err := url.Parse(baseURL)
	if err != nil {
		glog.Exitf("Failed to parse logURL %q", baseURL, err)
	}
	return func(ctx context.Context, p string) ([]byte, error) {
		u2, err := u.Parse(p)
		if err != nil {
			return nil, err
		}
		return readHTTP(ctx, u2)
	}
}

func readHTTP(ctx context.Context, u *url.URL) ([]byte, error) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case 404:
		glog.Infof("Not found: %q", u.String())
		return nil, os.ErrNotExist
	case 200:
		break
	default:
		return nil, fmt.Errorf("unexpected http status %q", resp.Status)
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func mustOpenZip(p string) *zip.Reader {
	f, err := os.Open(p)
	if err != nil {
		glog.Exitf("Failed to open zip file %q: %v", p, err)
	}
	info, err := f.Stat()
	if err != nil {
		glog.Exitf("Failed to stat zip file %q: %v", f, err)
	}
	z, err := zip.NewReader(f, info.Size())
	if err != nil {
		glog.Exitf("Failed to create zip file reader: %v", err)
	}
	return z
}

func mustRead(z *zip.Reader, n string) []byte {
	f, err := z.Open(n)
	if err != nil {
		glog.Exitf("Failed to open %q in zip: %v", n, err)
	}
	defer f.Close()

	r, err := ioutil.ReadAll(f)
	if err != nil {
		glog.Exitf("Failed to read %q from zip: %v", n, err)
	}
	return r
}

func mustOpenCP(cpRaw []byte, origin string, sigV note.Verifier) *log.Checkpoint {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, origin, sigV)
	if err != nil {
		glog.Exitf("Failed to open checkpoint: %v", err)
	}
	return cp
}

func mustReadIncProof(z *zip.Reader, n string) [][]byte {
	r := mustRead(z, n)

	const delim = "\n"
	s := string(r)
	if !strings.HasSuffix(s, delim) {
		glog.Exit("data should have trailing newline on last hash too")
	}
	lines := strings.Split(s, delim)
	// We expect there to be one too many fields here since the final hash
	// should be terminated with a newline too.
	lines = lines[:len(lines)-1]
	proof := make([][]byte, len(lines))
	for i, l := range lines {
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			glog.Exitf("Failed to decode proof line %d: %w", i, err)
		}
		proof[i] = b
	}
	return proof
}

func mustParseManifest(raw []byte) manifest {
	mf := manifest{}
	if err := json.Unmarshal(raw, &mf); err != nil {
		glog.Exitf("Failed to parse JSON: %v", err)
	}
	var err error
	mf.SHA256, err = hex.DecodeString(mf.SHA256Hex)
	if err != nil {
		glog.Exitf("Invalid hex in manifest %q: %v", mf.SHA256Hex, err)
	}
	return mf
}

func mustNewVerifier(v string) note.Verifier {
	sigV, err := note.NewVerifier(v)
	if err != nil {
		glog.Exitf("Failed to create verifier from %q: %v", v, err)

	}
	return sigV
}
