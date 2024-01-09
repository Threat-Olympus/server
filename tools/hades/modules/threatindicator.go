package modules

import (
	"bufio"
	"fmt"
	"os/exec"
)

func CheckDllInjection(messageChan chan string) {
	script := `
    $Path = 'C:\Windows\System32'
    $KnownDLLs = Get-Content 'HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs'
    $KnownDLLs | ForEach-Object {
        $FullPath = Join-Path -Path $Path -ChildPath $_.PSChildName
        if (!(Test-Path -Path $FullPath)) {
            Write-Output ("Potential DLL hijacking: " + $FullPath)
        }
    }
    `

	cmd := exec.Command("powershell", "-Command", script)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		messageChan <- fmt.Sprintln(err)
		return
	}

	if err := cmd.Start(); err != nil {
		messageChan <- fmt.Sprintln(err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		messageChan <- fmt.Sprintln(line)
	}

	if err := cmd.Wait(); err != nil {
		messageChan <- fmt.Sprintln(err)
		return
	}
}

func CheckProcessInjection(messageChan chan string) {
	script := `
	$Processes = Get-Process
	$Processes | ForEach-Object {
		$ProcessPath = $_.Path
		if ($ProcessPath -eq $null) {
			Write-Output ("Potential process injection: " + $_.Name)
		}
	}
	`

	cmd := exec.Command("powershell", "-Command", script)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		messageChan <- fmt.Sprintln(err)
		return
	}

	if err := cmd.Start(); err != nil {
		messageChan <- fmt.Sprintln(err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		messageChan <- fmt.Sprintln(line)
	}

	if err := cmd.Wait(); err != nil {
		messageChan <- fmt.Sprintln(err)
		return
	}
}
