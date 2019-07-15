package gotun2socks

import (
	"compress/gzip"
	"encoding/gob"
	"log"
	"os"
	"runtime/debug"
	"strings"

	"github.com/pmezard/adblock/adblock"

	goahocorasick "github.com/anknown/ahocorasick"
)

const MAX_RULES_PER_MATCHER = 1000
const MAX_CONTENT_SIZE_SCAN = 1000 * 1024 //500kb max to scan
var adblockMatcher *AdBlockMatcher

var defaultBlockPageContent = "%url% is blocked. Category %category%. Reason %reason%"

type MatcherCategory struct {
	Category string
	Matchers []*adblock.RuleMatcher
}

type PhraseCategory struct {
	Category  string
	Phrases   []string
	processor *goahocorasick.Machine
}

type AdBlockMatcher struct {
	MatcherCategories       []*MatcherCategory
	BypassMatcherCategories []*MatcherCategory
	PhraseCategories        []*PhraseCategory
	lastMatcher             *adblock.RuleMatcher
	RulesCnt                int
	phrasesCount            int
	bypassEnabled           bool
	BlockPageContent        string
}

func CreateMatcher() *AdBlockMatcher {
	adblockMatcher = &AdBlockMatcher{
		RulesCnt:         0,
		BlockPageContent: defaultBlockPageContent,
	}

	return adblockMatcher
}

func (am *AdBlockMatcher) addMatcher(category string, bypass bool) {
	matcher := adblock.NewMatcher()
	var categoryMatcher *MatcherCategory
	for _, element := range adblockMatcher.MatcherCategories {
		if element.Category == category {
			categoryMatcher = element
			break
		}
	}

	if categoryMatcher == nil {
		categoryMatcher = &MatcherCategory{
			Category: category,
		}

		if bypass {
			am.BypassMatcherCategories = append(am.BypassMatcherCategories, categoryMatcher)
		} else {
			am.MatcherCategories = append(am.MatcherCategories, categoryMatcher)
		}
	}

	categoryMatcher.Matchers = append(categoryMatcher.Matchers, matcher)
	adblockMatcher.lastMatcher = matcher
}

func (am *AdBlockMatcher) GetBlockPage(url string, category string, reason string) string {
	tagsReplacer := strings.NewReplacer("%url%", url,
		"%category%", category,
		"%reason%", reason)
	return tagsReplacer.Replace(am.BlockPageContent)
}

func (am *AdBlockMatcher) TestUrlBlocked(url string, host string) *string {
	res := am.matchRulesCategories(am.MatcherCategories, url, host)
	if res != nil {
		return res
	}

	if am.bypassEnabled {
		return nil
	}

	return am.matchRulesCategories(am.BypassMatcherCategories, url, host)
}

func (am *AdBlockMatcher) matchRulesCategories(matcherCategories []*MatcherCategory, url string, host string) *string {
	rq := &adblock.Request{
		URL:    url,
		Domain: host,
	}

	for _, matcherCategory := range matcherCategories {
		for _, matcher := range matcherCategory.Matchers {
			matched, _, err := matcher.Match(rq)
			if err != nil {
				log.Printf("Error matching rule %s", err)
			}

			if matched {
				return &matcherCategory.Category
			}
		}
	}

	return nil
}

func (am *AdBlockMatcher) TestContentTypeIsFiltrable(contentType string) bool {
	return strings.Contains(contentType, "html") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "text")
}

func (am *AdBlockMatcher) IsContentSmallEnoughToFilter(contentSize int64) bool {
	log.Printf("Content Size testing is %d, maxSize is %d", contentSize, MAX_CONTENT_SIZE_SCAN)

	return contentSize > 0 && contentSize < MAX_CONTENT_SIZE_SCAN
}

func (am *AdBlockMatcher) TestContainsForbiddenPhrases(str []byte) *string {
	text := []rune(strings.ToLower(string(str)))

	for _, phraseCategory := range am.PhraseCategories {
		res := phraseCategory.processor.MultiPatternSearch(text, true)
		if len(res) > 0 {
			return &phraseCategory.Category
		}
	}

	return nil
}

func (am *AdBlockMatcher) AddBlockedPhrase(phrase string, category string) {
	var phraseCategory *PhraseCategory = nil
	for _, element := range adblockMatcher.PhraseCategories {
		if element.Category == category {
			phraseCategory = element
			break
		}
	}

	if phraseCategory == nil {
		phraseCategory = &PhraseCategory{
			Category: category,
		}

		am.PhraseCategories = append(am.PhraseCategories, phraseCategory)
	}

	phraseCategory.Phrases = append(phraseCategory.Phrases, phrase)
}

func (am *AdBlockMatcher) Build() {
	am.phrasesCount = 0
	for _, phraseCategory := range am.PhraseCategories {
		processor := new(goahocorasick.Machine)

		dict := [][]rune{}
		for _, phrase := range phraseCategory.Phrases {
			dict = append(dict, []rune(strings.ToLower(phrase)))
		}
		processor.Build(dict)
		phraseCategory.processor = processor

		am.phrasesCount += len(phraseCategory.Phrases)
	}

	matchers := am.MatcherCategories[len(am.MatcherCategories)-1].Matchers
	am.lastMatcher = matchers[len(matchers)-1]

	debug.FreeOSMemory()
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

func (am *AdBlockMatcher) EnableBypass() {
	am.bypassEnabled = true
}

func (am *AdBlockMatcher) DisaleBypass() {
	am.bypassEnabled = false
}
