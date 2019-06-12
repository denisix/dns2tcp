package main

import (
	"fmt"
)

func main() {
	pos := 0
	arr := []int{1, 2, 3, 4, 5, 6, 7, 9}
	fmt.Println(arr) //[0 1 2 3 4 6 7 8 9]
	fmt.Println("input your position")
	fmt.Scanln(&pos)
	/* you need to check if negative input as well */
	if (pos < len(arr)){
		arr = append(arr[:pos], arr[pos+1:]...)
	} else {
		fmt.Println("position invalid")
	}
	fmt.Println(arr) //[0 1 2 3 4 6 7 8 9]
}
