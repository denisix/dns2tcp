package main

import "fmt"
import "time"

func Sepuha() {
	for {
		fmt.Println("Sepuha!")
		time.Sleep(2 * time.Second)
	}
}

func main() {
	fmt.Println("counting")

	go Sepuha()

	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		fmt.Println(i)
	}

	fmt.Println("done")
}
