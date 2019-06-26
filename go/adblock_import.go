package gotun2socks

import (
	"archive/zip"
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/pmezard/adblock/adblock"
)

func (am *AdBlockMatcher) ParseRulesZipArchive(filePath string) {
	zipFile, e := zip.OpenReader(filePath)
	if e != nil {
		log.Printf("Error parsing zipfile %s", e)
		return
	}
	defer zipFile.Close()
	for _, file := range zipFile.File {
		am.ParseZipRulesFile(file)
	}
}

func (am *AdBlockMatcher) AddRule(rule string) {
	r, e := adblock.ParseRule(rule)

	if e != nil {
		log.Printf("Error parsing rule %s %s", rule, e)
		return
	}
	if r == nil {
		log.Printf("Error parsing rule is nil")
		return
	}

	if am.RulesCnt%MAX_RULES_PER_MATCHER == 0 {
		am.addMatcher()
	}

	am.lastMatcher.AddRule(r, am.RulesCnt)

	am.RulesCnt = am.RulesCnt + 1
}

func (am *AdBlockMatcher) ParseRulesFile(filePath string) {
	file, err := os.Open(filePath)
	defer file.Close()

	if err != nil {
		log.Printf("Error open file %s %s", filePath, err)
		return
	}

	// Start reading from the file using a scanner.
	scanner := bufio.NewScanner(file)

	am.addRulesFromScanner(scanner)
}

func (am *AdBlockMatcher) ParseZipRulesFile(file *zip.File) {
	fileDescriptor, err := file.Open()
	defer fileDescriptor.Close()

	if err != nil {
		log.Printf("Error open zip file %s", err)
		return
	}

	scanner := bufio.NewScanner(fileDescriptor)
	if strings.Contains(file.Name, ".triggers") {
		log.Printf("Opening triggers %s", file.Name)
		am.addPhrasesFromScanner(scanner)
	} else if strings.Contains(file.Name, ".rules") {
		log.Printf("Opening rules %s", file.Name)
		am.addRulesFromScanner(scanner)
	} else {
		log.Printf("File type recognition failed %s", file.Name)
	}
}

func (am *AdBlockMatcher) addRulesFromScanner(scanner *bufio.Scanner) {
	for scanner.Scan() {
		line := scanner.Text()
		am.AddRule(line)
	}
}

func (am *AdBlockMatcher) addPhrasesFromScanner(scanner *bufio.Scanner) {
	for scanner.Scan() {
		line := scanner.Text()
		am.AddBlockedPhrase(line)
	}
}
