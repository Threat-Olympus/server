package posied0n

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"

	"github.com/posied0n/ruleengine"
)

func Posied0n(interfaceName string, dchannel chan<- string) {
	// Read rules from the default Snort rules file
	rulesFile := flag.String("rules", "/mnt/hgfs/GolandProjects/Threat-Olympus/tools/posied0n/rules/snort.rules", "Path to Snort rules file")
	flag.Parse()
	// Read rules from the file
	rules, err := readSnortRulesFromFile(*rulesFile)
	if err != nil {
		log.Fatal("Error reading rules:", err)
	}
	//fmt.Println(*rulesFile)
	// Create a RuleEngine with the provided rules
	engine := ruleengine.NewRuleEngine(rules)

	// Open the network interface for packet capture
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets from the interface and match against rules
	for packet := range packetSource.Packets() {
		// Extract relevant information from the packet
		srcport, dstport, srcip, dstip, content := extractPacketInfo(packet)

		// Create a packet string in the expected format for rule matching
		packetString := fmt.Sprintf("sPort:%s dPort:%s SIP:%s DIP:%s Content:%s", srcport, dstport, srcip, dstip, content)
		//fmt.Println(packetString)
		// Match against the rules and return alerts
		//fmt.Println(engine.Rules)
		engine.Match(packetString, dchannel)
	}
}

func extractPacketInfo(packet gopacket.Packet) (string, string, string, string, string) {
	// Extract relevant information from the packet (adjust parsing based on your data format)
	// For example, assuming the packet contains TCP and IP layers:
	var Sport, Dport, Sip, Dip, content string

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		Dport = fmt.Sprintf("%d", tcp.DstPort)
		Sport = fmt.Sprintf("%d", tcp.SrcPort)
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		Sip = ipLayer.(*layers.IPv4).SrcIP.String()
		Dip = ipLayer.(*layers.IPv4).DstIP.String()
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		content = string(appLayer.Payload())
	}

	return Sport, Dport, Sip, Dip, content
}

func readSnortRulesFromFile(filePath string) ([]ruleengine.Rule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []ruleengine.Rule
	scanner := bufio.NewScanner(file)
	var rule []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		//fmt.Println(line)
		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			// Assuming the Snort rule format is "alert tcp any any -> any any (content: "example"; msg: "Example Rule";)"
			rule = append(rule, line)
		}
	}
	//fmt.Println(rule[1])
	rules, _ = ruleengine.ParseSnortRules(rule)
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	//fmt.Println(rules)
	return rules, nil
}
