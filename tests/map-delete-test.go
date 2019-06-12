package main

import (
	"fmt"
)

func main () {
    var mapA = map[string] []int{};

    mapA["moo"] = []int{1, 2, 3};
    //mapA["ha"] = []int{1, 2, 3}

	for x, k := range mapA {
        fmt.Printf("- x=%v k=%v\n", x, k)

		l := len(mapA[x]);
		i := 0;
		fmt.Println(mapA)

		for i < l-1 {
			fmt.Printf("- x=%s, i=%d, l=%d\n", x, i, l)
			fmt.Printf("\t element=%v\n", mapA[x][i])

			l = len(mapA[x])
			mapA[x][l-1], mapA[x][i] = mapA[x][i], mapA[x][l-1]
			mapA[x] = mapA[x][:l-1]
			i--

			i++
			//mapA[x] = append(mapA[x][:i], mapA[x][i+1:]...)
			fmt.Println("- rr: ");
			fmt.Println(mapA)

			if l < 0 {
				break
			}
		}
		fmt.Println(" res: ")
		fmt.Println(mapA)

		//delete(mapA, x);
    }
}
