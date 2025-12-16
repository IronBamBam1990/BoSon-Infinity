package main

import "time"

func main() {
	StartNode()
	// prosta blokada, żeby proces nie wyszedł
	for {
		time.Sleep(24 * time.Hour)
	}
}
