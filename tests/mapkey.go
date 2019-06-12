package main

import "fmt"

type mapRec struct {
	ttl int16
	val string
    expires int64
}

type mapKey struct {
    rec		uint16
    domain	string
}

func main() {
    h := make(map[mapKey]mapRec)

    h[mapKey{0, "google.com"}] = mapRec{299, "172.217.16.46", 1551267287}
    h[mapKey{1, "github.com"}] = mapRec{59, "192.30.253.113", 1551267289}

    fmt.Printf("\n%+v\n\n", h)
}
