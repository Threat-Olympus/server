// ruleengine/ruleengine.go
package ruleengine

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule represents a Snort-like rule with protocol, source/destination IP, source/destination port, and options
type Rule struct {
	Protocol        string
	SourceIP        string
	SourcePort      string
	DestinationIP   string
	DestinationPort string
	Content         string
	msg             []string
}

// RuleEngine represents the Snort-like rule engine
type RuleEngine struct {
	Rules []Rule
}

// NewRuleEngine creates a new RuleEngine with the provided rules
func NewRuleEngine(rules []Rule) *RuleEngine {
	//fmt.Println(rules[1])
	return &RuleEngine{Rules: rules}
}
func extractMsg(snortRule string) ([]string, error) {
	// Define a regular expression to match the 'msg' part of a Snort rule
	re := regexp.MustCompile(`\bmsg\s*:\s*("|')(.*?)("|')`)

	// Find the match in the Snort rule
	match := re.FindStringSubmatch(snortRule)

	// Check if a match is found
	if len(match) >= 1 {
		return match, nil
	}

	return nil, fmt.Errorf("msg not found in the Snort rule")
}

// ParseSnortRule parses a Snort rule and returns a Rule object
func ParseSnortRule1(snortRule string) (Rule, error) {
	parts := strings.Fields(snortRule)
	if len(parts) >= 5 && parts[0] == "alert" {
		protocol := parts[1]
		sourceIP := parts[2]
		sourcePort := parts[3]
		destinationIP := parts[5]
		destinationPort := parts[6]
		content := parts[9]
		msg, _ := extractMsg(snortRule)
		return Rule{
			Protocol:        protocol,
			SourceIP:        sourceIP,
			SourcePort:      sourcePort,
			DestinationIP:   destinationIP,
			DestinationPort: destinationPort,
			Content:         content,
			msg:             msg,
		}, nil
	}

	return Rule{}, fmt.Errorf("invalid Snort rule format: %s", snortRule)
}

// ParseSnortRules parses multiple Snort rules and returns a slice of Rule objects
func ParseSnortRules(snortRules []string) ([]Rule, error) {
	var parsedRules []Rule
	for _, snortRule := range snortRules {
		rule, err := ParseSnortRule1(snortRule)
		if err != nil {
			return nil, err
		}
		parsedRules = append(parsedRules, rule)
		//fmt.Println(parsedRules)
	}
	return parsedRules, nil
}

// Match checks if the given packet matches any rule in the rule engine
func (re *RuleEngine) Match(packet string, dchan chan<- string) {
	fmt.Println("Match started 1")
	for i, _ := range re.Rules {
		//fmt.Println("match loop", re.Rules[i])
		if re.matchRule(packet, re.Rules[i]) {
			fmt.Println("Packet matched rule:", re.Rules[i].msg[0])
			data := fmt.Sprintln("Packet matched rule:", re.Rules[i].msg[0])
			dchan <- data
			// Perform action or logging here
		}
	}
}

// matchRule checks if the packet matches the specified rule
func (re *RuleEngine) matchRule(packet string, rule Rule) bool {
	fmt.Println("Matchrule started")
	// Match against source IP
	if rule.SourceIP != "any" && rule.SourceIP != "" && rule.SourceIP != strings.ToLower(packet) {
		return false
	}

	// Match against source port
	if rule.SourcePort != "any" && rule.SourcePort != "" && rule.SourcePort != strings.ToLower(packet) {
		return false
	}

	// Match against destination IP
	if rule.DestinationIP != "any" && rule.DestinationIP != "" && rule.DestinationIP != strings.ToLower(packet) {
		return false
	}

	// Match against destination port
	if rule.DestinationPort != "any" && rule.DestinationPort != "" && rule.DestinationPort != strings.ToLower(packet) {
		return false
	}

	// Match against options (dummy implementation)
	//if rule.Content != "" && rule.Content != strings.ToLower(packet) {
	//	return false
	//}
	//fmt.Println("Match working")
	return true

}

// Example usage:
// rule, err := ParseSnortRule("alert tcp any any -> any any (content: \"example\"; msg: \"Example Rule\";)")
// if err != nil {
//     fmt.Println("Error parsing Snort rule:", err)
// } else {
//     fmt.Println("Parsed Snort rule:", rule)
// }
