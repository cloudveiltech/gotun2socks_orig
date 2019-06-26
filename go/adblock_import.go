package gotun2socks

import (
	"archive/zip"
	"bufio"
	"io/ioutil"
	"log"
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

func (am *AdBlockMatcher) AddRule(rule string, category string) {
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
		am.addMatcher(category)
	}

	am.lastMatcher.AddRule(r, am.RulesCnt)

	am.RulesCnt = am.RulesCnt + 1
}

func (am *AdBlockMatcher) ParseZipRulesFile(file *zip.File) {
	fileDescriptor, err := file.Open()
	defer fileDescriptor.Close()

	if err != nil {
		log.Printf("Error open zip file %s", err)
		return
	}

	if strings.Contains(file.Name, "block.htm") {
		am.addBlockPageFromZipFile(file)
	} else {
		scanner := bufio.NewScanner(fileDescriptor)
		if strings.Contains(file.Name, ".triggers") {
			log.Printf("Opening triggers %s", file.Name)
			am.addPhrasesFromScanner(scanner, file.Name)
		} else if strings.Contains(file.Name, ".rules") {
			log.Printf("Opening rules %s", file.Name)
			am.addRulesFromScanner(scanner, file.Name)
		} else {
			log.Printf("File type recognition failed %s", file.Name)
		}
	}
}

func (am *AdBlockMatcher) addBlockPageFromZipFile(file *zip.File) {
	fileReader, e := file.Open()
	if e != nil {
		log.Printf("Error reading block page %s %s", e, file.Name)
	}
	defer fileReader.Close()
	content, e := ioutil.ReadAll(fileReader)
	if e != nil {
		log.Printf("Error reading block page %s %s", e, file.Name)
	}
	am.BlockPageContent = string(content)
}

func (am *AdBlockMatcher) addRulesFromScanner(scanner *bufio.Scanner, categoryName string) {
	for scanner.Scan() {
		line := scanner.Text()
		am.AddRule(line, categoryName)
	}
}

func (am *AdBlockMatcher) addPhrasesFromScanner(scanner *bufio.Scanner, categoryName string) {
	for scanner.Scan() {
		line := scanner.Text()
		am.AddBlockedPhrase(line, categoryName)
	}
}
