# Hades

Hades is a system-level threat hunting tool written in Golang.

## Introduction

Hades is designed to detect and investigate potential threats at the system level. It leverages various techniques and algorithms to analyze system behavior and identify suspicious activities.

## Features

- Real-time monitoring of system events
- Detection of known threat indicators
- Behavior-based anomaly detection
- Integration with threat intelligence feeds
- Extensible and customizable rule engine

## Installation

To install Hades, follow these steps:

1. Clone the repository:

   ```shell
   git clone https://github.com/h3athen/hades.git
   ```

2. Build the project:

   ```shell
   cd hades
   go build
   ```

3. Run Hades:

   ```shell
   ./hades -h
   ```

## Usage

```
Usage of hades:
  -cpu
        Monitor CPU usage
  -event
        Monitor Windows log events
  -fsm
        Monitor file system events
  -help
        Show help
  -mem
        Monitor memory usage
  -net
        Monitor network events
  -path string
        path to file monitor (default ".")
```