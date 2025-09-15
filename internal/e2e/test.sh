export BBB_AZBLOB_ENDPOINT=http://%s.blob.localhost:10000/
export BBB_AZBLOB_ACCOUNTKEY=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==
export BBB_TEST_BIN_PATH=./bbb

go build -o $BBB_TEST_BIN_PATH ../..

go test -v