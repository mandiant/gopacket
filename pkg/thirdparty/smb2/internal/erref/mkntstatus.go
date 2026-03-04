// +build ignore

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func main() {
	doc, err := goquery.NewDocument("https://msdn.microsoft.com/en-us/library/cc704588.aspx")
	if err != nil {
		panic(err)
	}

	type entry struct {
		key string
		val string
		str string
	}

	var entries []entry

	doc.Find("table tr").Each(func(_ int, s *goquery.Selection) {
		pairs := s.Find("td")
		if pairs.Length() == 2 {
			keyValuePair := pairs.Eq(0).Find("p")
			key := keyValuePair.Eq(1).Text()
			val := keyValuePair.Eq(0).Text()
			str := strings.Replace(pairs.Eq(1).Find("p").Text(), "\n  ", " ", -1)

			entries = append(entries, entry{
				key: key,
				val: val,
				str: str,
			})
		}
	})

	fmt.Println("package erref")

	fmt.Println("type NtStatus uint32")

	fmt.Println("func (e NtStatus) Error() string {")
	fmt.Println("\treturn ntStatusStrings[e]")
	fmt.Println("}")

	fmt.Println("const (")
	for _, e := range entries {
		fmt.Printf("\t%s\tNtStatus\t=\t%s\n", e.key, e.val)
	}
	fmt.Println(")")

	fmt.Println("var ntStatusStrings = map[NtStatus]string{")
	m := make(map[string]bool)
	for _, e := range entries {
		if !m[e.val] {
			fmt.Printf("\t%s:\t%s,\n", e.key, strconv.Quote(e.str))
		}
		m[e.val] = true
	}
	fmt.Println("}")
}
