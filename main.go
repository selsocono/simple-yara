package main

import (
	"flag"
	"github.com/hillu/go-yara"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func main() {

	rules := flag.String("rules", "", `path to file with rules. example: C:\test.yar`)
	dir := flag.String("dir", "", `path to scan file or directory. example: C:\Windows\System32\calc.exe`)
	flag.Parse()

	if *rules == "" || *dir == "" {
		flag.PrintDefaults()
		return
	}

	file, err := ioutil.ReadFile(*rules)
	if err != nil {
		log.Println(err)
		return
	}

	c, err := yara.NewCompiler()
	if c == nil || err != nil {
		log.Println(err)
		return
	}

	if err = c.AddString(string(file), ""); err != nil {
		log.Println(err)
		return
	}

	r, err := c.GetRules()
	if err != nil {
		log.Println(err)
		return
	}

	err = filepath.Walk(*dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			log.Println(err)
			return nil
		}

		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Println(err)
			}
		}(file)

		var mr yara.MatchRules
		err = r.ScanFileDescriptor(file.Fd(), 0, 0, &mr)
		if err != nil {
			log.Println(err)
			return nil
		}

		if len(mr) > 0 {
			for _, m := range mr {
				log.Printf("%s %s", m.Rule, path)
			}
		}
		return nil
	})
}
