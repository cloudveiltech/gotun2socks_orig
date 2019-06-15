package gotun2socks

import (
	"compress/gzip"
	"encoding/gob"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/pmezard/adblock/adblock"
)

const MAX_RULES_PER_MATCHER = 1000
const MAX_CONTENT_SIZE_SCAN = 100 * 1024 //100kb max to scan
var adblockMatcher *AdBlockMatcher

type AdBlockMatcher struct {
	Matchers     []*adblock.RuleMatcher
	Phrases      []string
	lastMatcher  *adblock.RuleMatcher
	RulesCnt     int
	regexp       *regexp.Regexp
	phrasesCount int
}

func CreateMatcher() *AdBlockMatcher {
	adblockMatcher = &AdBlockMatcher{
		RulesCnt: 0,
	}

	adblockMatcher.addMatcher()

	return adblockMatcher
}

func (am *AdBlockMatcher) addMatcher() {
	matcher := adblock.NewMatcher()
	adblockMatcher.Matchers = append(adblockMatcher.Matchers, matcher)
	adblockMatcher.lastMatcher = matcher
}

func (am *AdBlockMatcher) TestUrlBlocked(url string, host string) bool {
	if len(am.Matchers) == 0 {
		return false
	}

	rq := &adblock.Request{
		URL:    url,
		Domain: host,
	}

	for _, matcher := range am.Matchers {
		matched, _, err := matcher.Match(rq)
		if err != nil {
			log.Printf("Error matching rule %s", err)
		}

		if matched {
			return true
		}
	}

	return false
}

func (am *AdBlockMatcher) TestContentTypeIsFiltrable(contentType string) bool {
	return strings.Contains(contentType, "html") || strings.Contains(contentType, "json")
}

func (am *AdBlockMatcher) IsContentSmallEnoughToFilter(contentSize int64) bool {
	return contentSize < MAX_CONTENT_SIZE_SCAN
}

func (am *AdBlockMatcher) TestContainsForbiddenPhrases(str []byte) []byte {
	if am.regexp == nil {
		return nil
	}

	return am.regexp.Find(str)
}

func (am *AdBlockMatcher) AddBlockedPhrase(phrase string) {
	am.Phrases = append(am.Phrases, regexp.QuoteMeta(phrase))
}

func (am *AdBlockMatcher) Build() {
	regexString := strings.Join(am.Phrases, "|")
	var e error
	am.regexp, e = regexp.Compile(regexString)
	if e != nil {
		log.Printf("Error compiling matcher %s", e)
	}
	am.phrasesCount = len(am.Phrases)
	am.lastMatcher = am.Matchers[len(am.Matchers)-1]
}

func (am *AdBlockMatcher) RulesCount() int {
	return am.RulesCnt
}

func (am *AdBlockMatcher) PhrasesCount() int {
	return am.phrasesCount
}

func (am *AdBlockMatcher) SaveToFile(filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		log.Printf("Error opening file %s %s", filePath, err)
		return
	}
	defer file.Close()

	stream := gzip.NewWriter(file)
	defer stream.Close()

	encoder := gob.NewEncoder(stream)
	err = encoder.Encode(am)
	if err != nil {
		log.Printf("Encoder error %s", err)
	}
}

func LoadMatcherFromFile(filePath string) *AdBlockMatcher {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file %s %s", filePath, err)
		return nil
	}
	defer file.Close()

	stream, err := gzip.NewReader(file)
	if err != nil {
		log.Printf("Error opening file %s %s", filePath, err)
		return nil
	}
	defer stream.Close()

	decoder := gob.NewDecoder(stream)

	adblockMatcher = &AdBlockMatcher{
		RulesCnt: 0,
	}
	err = decoder.Decode(&adblockMatcher)
	if err != nil {
		log.Printf("Decoder error %s", err)
	}
	return adblockMatcher
}
