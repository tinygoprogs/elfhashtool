package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	getopt "github.com/kesselborn/go-getopt"
)

type BBFunc func([]byte) []byte
type ESFunc func([]byte) string

var (
	hashfuncs = map[string]BBFunc{
		"sha1":   func(data []byte) []byte { r := sha1.Sum(data); return r[:] },
		"sha256": func(data []byte) []byte { r := sha256.Sum224(data); return r[:] },
		"sha512": func(data []byte) []byte { r := sha512.Sum512(data); return r[:] },
	}
	hashfunc BBFunc

	encfuncs = map[string]ESFunc{
		"64":     base64.StdEncoding.EncodeToString,
		"base64": base64.StdEncoding.EncodeToString,
		"hex":    hex.EncodeToString,
	}
	encfunc ESFunc
)

func hash_n_enc(data []byte) string {
	sha := hashfunc(data)
	return encfunc(sha[:])
}

func DumpSectionHashes(fd *elf.File, format, hashstr, encstr string) {
	fmt.Printf(format, "Name", encstr+"("+hashstr+"(data))")
	fmt.Printf(format, "-", "-")
	for _, section := range fd.Sections {
		if section == nil {
			panic("nil section")
		}
		s := *section
		sh := s.SectionHeader
		data, _ := s.Data()
		//if err != nil {
		//	// happens usually for .bss as that section only exists in memory
		//	msg := fmt.Sprintf("err getting data: %s", err.Error())
		//	fmt.Printf(format, sh.Name, msg)
		//	continue
		//}
		fmt.Printf(format, sh.Name, hash_n_enc(data))
	}
}

func pepare_opts() *getopt.Options {
	var algo_names []string
	for key := range hashfuncs {
		algo_names = append(algo_names, key)
	}
	hash_algos := fmt.Sprintf("hash algorithm e %v", algo_names)

	var hash_names []string
	for key := range encfuncs {
		hash_names = append(hash_names, key)
	}
	encoding_algos := fmt.Sprintf("encoding e %v", hash_names)

	defs := []getopt.Option{
		{"hash-algo|a", hash_algos, getopt.Optional | getopt.ExampleIsDefault, "sha256"},
		{"encoding|e", encoding_algos, getopt.Optional | getopt.ExampleIsDefault, "hex"},
		{"file|f", "elf target file", getopt.IsArg | getopt.Required, ""},
	}
	opts := getopt.Options{
		Description: "hash single sections of elf files, similar to `r2 -q -c 'iS sha1'`",
		Definitions: defs,
	}
	return &opts
}

func main() {
	var exist bool

	opts := pepare_opts()
	o, a, _, e := opts.ParseCommandLine()
	if e != nil || len(a) == 0 {
		fmt.Print(opts.Help())
		if e != nil {
			fmt.Println(e)
		}
		return
	}

	hashstr := o["hash-algo"].String
	hashfunc, exist = hashfuncs[hashstr]
	if !exist {
		fmt.Print(opts.Usage())
		fmt.Printf("Error: unknown hash '%s'\n", hashstr)
		return
	}

	encstr := o["encoding"].String
	encfunc, exist = encfuncs[encstr]
	if !exist {
		fmt.Print(opts.Usage())
		fmt.Printf("Error: unknown encoding '%s'\n", encstr)
		return
	}

	file, err := elf.Open(a[0])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	DumpSectionHashes(file, " %-20s | %s\n", hashstr, encstr)
}
