package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"hades"
	"net"
	"os/exec"
	"posied0n"
	"runtime"
	"strings"

	//"hades"
	"net/http"
	"z3us"
)

type Data struct {
	Message string `json:"message"`
}

var pos = 0

func main() {
	dataChannel := make(chan string)
	dataChannel1 := make(chan string)
	r := gin.Default()

	// Serve static files from the "static" directory
	r.Static("/static", "./static")

	// Load HTML templates from the "templates" directory
	r.LoadHTMLGlob("templates/*")

	// Define the main page
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	r.GET("/zeus.html", func(c *gin.Context) {
		c.HTML(http.StatusOK, "zeus.html", nil)
	})
	r.GET("/posi.html", func(c *gin.Context) {
		c.HTML(http.StatusOK, "posi.html", nil)
	})
	r.GET("/hades.html", func(c *gin.Context) {
		c.HTML(http.StatusOK, "hades.html", nil)
	})
	// Handle form submission

	r.POST("/zeus", func(c *gin.Context) {
		// Get the URL from the form submission
		userInputURL := c.PostForm("url")
		userInputPaths := c.PostForm("paths")
		pathsToTest := strings.Split(userInputPaths, ",")
		// Run the Z3us function and get the results
		result := z3us.Z3us(userInputURL, pathsToTest)

		// Render the results on the same page
		c.HTML(http.StatusOK, "zeus.html", gin.H{"result": result})
	})

	//Posss

	r.GET("/get-data-pos", func(c *gin.Context) {
		message := <-dataChannel
		data := Data{Message: message}
		c.JSON(http.StatusOK, data)
	})

	r.GET("/interfaces", func(c *gin.Context) {
		interfaces, err := getNetworkInterfaces()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"interfaces": interfaces})
	})
	r.POST("/posied0n", func(c *gin.Context) {
		if pos == 0 {
			pos = 1
			// Get the interface from the form submission
			interfaceName := c.PostForm("interface")
			//interfaceName := "Wi-Fi"
			fmt.Println(interfaceName)
			// Start posied0n in a separate Goroutine
			go posied0n.Posied0n(interfaceName, dataChannel)

		}
		c.HTML(http.StatusOK, "posi.html", gin.H{"message": "Packet capture started successfully"})
	})
	r.POST("/hades", func(c *gin.Context) {

		flg := c.PostForm("flag")
		go hades.Hades(flg, dataChannel1)

		c.HTML(http.StatusOK, "hades.html", gin.H{"message": "Scanning in progress"})
	})
	r.GET("/get-data-had", func(c *gin.Context) {
		message := <-dataChannel1
		data := Data{Message: message}
		c.JSON(http.StatusOK, data)
	})

	// Start the server on port 8080
	r.Run(":8080")

}

func getNetworkInterfaces() ([]string, error) {
	interfaces := []string{}

	if runtime.GOOS == "windows" {
		// On Windows, use the net package to get network interfaces
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}

		for _, iface := range ifaces {
			interfaces = append(interfaces, iface.Name)
			fmt.Println(iface.Name)
		}
	} else {
		// On Unix-like systems, use the ifconfig command
		cmd := exec.Command("ifconfig")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, err
		}

		// Parse the output to extract interface names
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				interfaces = append(interfaces, fields[0])
			}
		}
	}

	return interfaces, nil
}
