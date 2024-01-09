package hades

import (
	"flag"
	"fmt"
	"hades/modules"
	"os"
	"strings"
	"time"
)

var (
	help   *bool
	net    *bool
	event  *bool
	cpu    *bool
	mem    *bool
	fsm    *bool
	path   *string
	threat *bool
)

func init() {
	help = flag.Bool("help", false, "Show help")
	net = flag.Bool("net", false, "Monitor network events")
	event = flag.Bool("event", false, "Monitor Windows log events")
	cpu = flag.Bool("cpu", false, "Monitor CPU usage")
	mem = flag.Bool("mem", false, "Monitor memory usage")
	fsm = flag.Bool("fsm", false, "Monitor file system events")
	path = flag.String("path", ".", "path to file monitor")
	threat = flag.Bool("threat", false, "Detect known threat indicators")
}

func Hades(flags string, messageChan chan string) {
	flagSet := flag.NewFlagSet("Hades", flag.ExitOnError)
	args := strings.Fields(flags)
	help = flagSet.Bool("help", false, "Show help")
	net = flagSet.Bool("net", false, "Monitor network events")
	event = flagSet.Bool("event", false, "Monitor Windows log events")
	cpu = flagSet.Bool("cpu", false, "Monitor CPU usage")
	mem = flagSet.Bool("mem", false, "Monitor memory usage")
	fsm = flagSet.Bool("fsm", false, "Monitor file system events")
	path = flagSet.String("path", ".", "path to file monitor")
	threat = flagSet.Bool("threat", false, "Detect known threat indicators")
	flagSet.Parse(args)

	if *help {
		flagSet.Usage()
		os.Exit(0)
	}

	if *net {
		modules.NetworkEvents(messageChan)
		os.Exit(0)
	}

	if *event {
		modules.LogEvents(messageChan)
		os.Exit(0)
	}

	if *cpu {
		modules.MonitorCPU(messageChan)
	}

	if *mem {
		modules.MonitorMemory(messageChan)
	}

	if *fsm {
		if *path != "." {
			modules.MonitorFileSystem(*path, messageChan)
		} else {
			fmt.Println("[-]: Path is not set")
		}
	}

	if *threat {
		fmt.Println("[+] Checking for DLL injection...")
		modules.CheckDllInjection(messageChan)
		time.Sleep(2 * time.Second)
		fmt.Println("[+] Checking for process injection...")
		modules.CheckProcessInjection(messageChan)
	}

}
