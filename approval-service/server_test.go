package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignAndVerifySignature(t *testing.T) {
	intent, err := base64.StdEncoding.DecodeString("eyJPcGVyYXRpb25UeXBlIjoidHJhbnNmZXIiLCJPcGVyYXRpb25JRCI6IjJuY2p4em9zMGNiRW9QWUM4S0hLdHkxajRuTCIsIlRpbWVzdGFtcCI6IjIwMjQtMTAtMThUMTk6MjQ6NTguMTEwOTA3Mjk3WiIsIkFzc2V0IjoiRVRIIiwiVGVzdE5ldHdvcmsiOnRydWUsIlNvdXJjZSI6InRlc3QxIiwiTWFzdGVyS2V5TmFtZSI6IkRlZmF1bHQiLCJEZXN0aW5hdGlvblR5cGUiOiJpbnRlcm5hbCIsIkRlc3RpbmF0aW9uQW1vdW50cyI6W3siRGVzdGluYXRpb24iOiJ0ZXN0MiIsIk1hc3RlcktleU5hbWUiOiJEZWZhdWx0IiwiQW1vdW50IjoiMC4wMDEifV0sIk1heEZlZSI6IiJ9")
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signature, err := signIntent(privateKey, intent)
	require.NoError(t, err)

	err = verifySignature(intent, getPublicKey(privateKey), signature)
	require.NoError(t, err)
}
