// Command nested is another module: never loaded.
package main

import "time"

func main() {
	go main()
	time.Sleep(1)
}
