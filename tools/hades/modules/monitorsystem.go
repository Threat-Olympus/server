// Real-time monitoring of system events
package modules

import (
	"bufio"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Monitor Nework Events
func NetworkEvents(messageChan chan string) {
	cmd := exec.Command("netstat", "-a")

	output, err := cmd.StdoutPipe()
	if err != nil {
		messageChan <- fmt.Sprintln("Error creating StdoutPipe for Cmd", err)
		return
	}

	if err := cmd.Start(); err != nil {
		messageChan <- fmt.Sprintln("Error starting Cmd", err)
		return
	}

	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "LISTEN") {
			messageChan <- fmt.Sprintln("Potential threat detected:", line)
		}
	}

	if err := cmd.Wait(); err != nil {
		messageChan <- fmt.Sprintln("Error waiting for Cmd", err)
		return
	}
}

// Monitor Windows Log Events
func LogEvents(messageChan chan string) {
	cmd := exec.Command("wevtutil", "qe", "System", "/f:text")

	output, err := cmd.StdoutPipe()
	if err != nil {
		messageChan <- fmt.Sprintln("Error creating StdoutPipe for Cmd", err)
		return
	}

	if err := cmd.Start(); err != nil {
		messageChan <- fmt.Sprintln("Error starting Cmd", err)
		return
	}

	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Error") {
			messageChan <- fmt.Sprintln("Potential threat detected:", line)
		}
	}

	if err := cmd.Wait(); err != nil {
		messageChan <- fmt.Sprintln("Error waiting for Cmd", err)
		return
	}
}

// Monitor CPU Usage
func MonitorCPU(messageChan chan string) {
	for {
		// Print the current CPU usage
		messageChan <- fmt.Sprintln("Current CPU usage: %f%%\n", float64(runtime.NumCPU())/float64(runtime.NumGoroutine())*100)
		time.Sleep(1 * time.Second)
	}
}

// Monitor Memory Usage
func MonitorMemory(messageChan chan string) {
	for {
		// Print the current memory usage
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		messageChan <- fmt.Sprintln("Current memory usage: %v bytes\n", m.Alloc)
		time.Sleep(1 * time.Second)
	}
}

// Monitor File System
func MonitorFileSystem(path string, messageChan chan string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		messageChan <- fmt.Sprintln(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				messageChan <- fmt.Sprintln("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					messageChan <- fmt.Sprintln("modified file:", event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				messageChan <- fmt.Sprintln("error:", err)
			}
		}
	}()

	err = watcher.Add(path)
	if err != nil {
		messageChan <- fmt.Sprintln(err)
	}
	<-done
}
