package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/svcctl"
	"gopacket/pkg/flags"
	"gopacket/pkg/remcomsvc"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	copyFile    = flag.String("c", "", "Copy the filename for later execution, arguments are passed in the command option")
	exePath     = flag.String("path", "", "Path of the command to execute")
	exeFile     = flag.String("file", "", "Alternative RemCom binary (be sure it doesn't require CRT)")
	serviceName = flag.String("service-name", "", "The name of the service used to trigger the payload")
	remoteName  = flag.String("remote-binary-name", "", "This will be the name of the executable uploaded on the target")
	codec       = flag.String("codec", "", "Sets encoding used (codec) from the target's output (default \"utf-8\")")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Setup Logging
	log := zerolog.New(os.Stderr)
	if !opts.Debug {
		log = zerolog.New(io.Discard)
	}

	// Connect via SMB
	log.Info().Msgf("Connecting to %s via SMB...", target.Host)
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	// Open SVCCTL pipe
	svcPipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open svcctl pipe: %v\n", err)
		os.Exit(1)
	}
	defer svcPipe.Close()

	// Bind SVCCTL
	svcRPC := dcerpc.NewClient(svcPipe)
	if err := svcRPC.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to bind svcctl: %v\n", err)
		os.Exit(1)
	}

	sc, err := svcctl.NewServiceController(svcRPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create service controller: %v\n", err)
		os.Exit(1)
	}
	defer sc.Close()

	// Create executor
	executor := &PSExec{
		sc:          sc,
		smbClient:   smbClient,
		target:      target,
		creds:       &creds,
		serviceName: *serviceName,
		remoteName:  *remoteName,
		copyFile:    *copyFile,
		exeFile:     *exeFile,
		exePath:     *exePath,
		log:         log,
	}

	// Get command - default to cmd.exe
	command := opts.Command()
	if command == "" {
		command = "cmd.exe"
	}

	// If -c is specified, prepend the copied file to the command
	if *copyFile != "" {
		baseName := *copyFile
		if idx := strings.LastIndexAny(*copyFile, "/\\"); idx >= 0 {
			baseName = (*copyFile)[idx+1:]
		}
		if command == "cmd.exe" {
			command = baseName
		} else {
			command = baseName + " " + command
		}
	}

	if err := executor.run(command); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
		executor.cleanup()
		os.Exit(1)
	}
}

// PSExec handles remote command execution via RemComSvc
type PSExec struct {
	sc          *svcctl.ServiceController
	smbClient   *smb.Client
	target      session.Target
	creds       *session.Credentials
	serviceName string
	remoteName  string
	copyFile    string
	exeFile     string
	exePath     string
	log         zerolog.Logger

	// Track for cleanup
	uploadedBinary string
	uploadedCopy   string
	createdSvc     string
	share          string
}

func (e *PSExec) run(command string) error {
	// Find writable share (prefer ADMIN$)
	shares := []string{"ADMIN$", "C$"}
	var shareFound string

	for _, share := range shares {
		if err := e.smbClient.UseShare(share); err == nil {
			shareFound = share
			e.share = share
			fmt.Printf("[*] Found writable share %s\n", share)
			break
		}
	}

	if shareFound == "" {
		return fmt.Errorf("no writable share found")
	}

	// Determine binary name
	binName := e.remoteName
	if binName == "" {
		binName = generateRandomString(8) + ".exe"
	}
	e.uploadedBinary = binName

	// Get binary data (either from file or embedded)
	var binData []byte
	if e.exeFile != "" {
		data, err := os.ReadFile(e.exeFile)
		if err != nil {
			return fmt.Errorf("failed to read exe file: %v", err)
		}
		binData = data
	} else {
		binData = remcomsvc.Binary
	}

	// Upload RemComSvc binary
	fmt.Printf("[*] Uploading file %s\n", binName)
	if err := e.uploadBytes(binName, binData); err != nil {
		return fmt.Errorf("failed to upload binary: %v", err)
	}

	// If -c specified, also upload that file
	if e.copyFile != "" {
		copyData, err := os.ReadFile(e.copyFile)
		if err != nil {
			return fmt.Errorf("failed to read copy file: %v", err)
		}
		copyName := e.copyFile
		if idx := strings.LastIndexAny(e.copyFile, "/\\"); idx >= 0 {
			copyName = e.copyFile[idx+1:]
		}
		e.uploadedCopy = copyName
		fmt.Printf("[*] Uploading file %s\n", copyName)
		if err := e.uploadBytes(copyName, copyData); err != nil {
			return fmt.Errorf("failed to upload copy file: %v", err)
		}
	}

	// Determine service name
	svcName := e.serviceName
	if svcName == "" {
		svcName = generateRandomString(4)
	}
	e.createdSvc = svcName

	// Build binary path
	var binPath string
	if shareFound == "ADMIN$" {
		binPath = "%SystemRoot%\\" + binName
	} else {
		binPath = fmt.Sprintf("\\\\127.0.0.1\\%s\\%s", shareFound, binName)
	}

	// Create service
	fmt.Printf("[*] Opening SVCManager on %s.....\n", e.target.Host)
	fmt.Printf("[*] Creating service %s on %s.....\n", svcName, e.target.Host)
	e.log.Debug().Msgf("Service binary path: %s", binPath)

	svcHandle, err := e.sc.CreateService(svcName, svcName, binPath,
		svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)

	if err != nil {
		// Service might already exist
		if strings.Contains(err.Error(), "0x00000431") {
			h, openErr := e.sc.OpenService(svcName, svcctl.SERVICE_ALL_ACCESS)
			if openErr == nil {
				e.sc.DeleteService(h)
				e.sc.CloseServiceHandle(h)
			}
			// Retry
			svcHandle, err = e.sc.CreateService(svcName, svcName, binPath,
				svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
		}

		if err != nil {
			return fmt.Errorf("create service failed: %v", err)
		}
	}

	// Start service
	fmt.Printf("[*] Starting service %s.....\n", svcName)
	startErr := e.sc.StartService(svcHandle)
	if startErr != nil {
		e.log.Debug().Msgf("Service start returned: %v (this is often expected)", startErr)
	}

	// Close service handle (we'll reopen for cleanup)
	e.sc.CloseServiceHandle(svcHandle)

	// Give service time to create pipes
	time.Sleep(500 * time.Millisecond)

	// Connect to RemCom communication pipe
	fmt.Println("[!] Press help for extra shell commands")

	if err := e.runShell(command); err != nil {
		return err
	}

	return nil
}

func (e *PSExec) runShell(command string) error {
	// Generate machine identifier and process ID for pipe naming
	machine := generateRandomString(4)
	processID := uint32(os.Getpid())

	// Open communication pipe
	commPipe, err := e.waitForPipe(remcomsvc.CommunicationPipe, 50)
	if err != nil {
		return fmt.Errorf("failed to open communication pipe: %v", err)
	}
	defer commPipe.Close()

	// Send command message
	msg := remcomsvc.NewMessage(command, e.exePath, machine, processID)
	if _, err := commPipe.Write(msg.Bytes()); err != nil {
		return fmt.Errorf("failed to send command: %v", err)
	}

	// Build pipe names
	stdoutPipeName := remcomsvc.PipeName(remcomsvc.StdoutPipePrefix, machine, processID)
	stdinPipeName := remcomsvc.PipeName(remcomsvc.StdinPipePrefix, machine, processID)
	stderrPipeName := remcomsvc.PipeName(remcomsvc.StderrPipePrefix, machine, processID)

	// Create channels for coordination
	done := make(chan struct{})
	var wg sync.WaitGroup

	// Channel to track last sent data for echo suppression
	lastSent := make(chan []byte, 1)
	lastSent <- nil // Initialize with nil

	// Stdout reader goroutine - needs separate SMB connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.pipeReaderWithEchoSuppress("stdout", stdoutPipeName, os.Stdout, done, lastSent)
	}()

	// Stderr reader goroutine - needs separate SMB connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.pipeReader("stderr", stderrPipeName, os.Stderr, done)
	}()

	// Stdin writer goroutine - needs separate SMB connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.pipeWriterWithEcho("stdin", stdinPipeName, os.Stdin, done, lastSent)
	}()

	// Wait for response on communication pipe
	respBuf := make([]byte, remcomsvc.ResponseSize)
	_, err = commPipe.Read(respBuf)
	if err != nil && err != io.EOF {
		e.log.Debug().Msgf("Error reading response: %v", err)
	}

	resp := remcomsvc.ParseResponse(respBuf)
	if resp != nil {
		fmt.Printf("[*] Process %s finished with ErrorCode: %d, ReturnCode: %d\n",
			command, resp.ErrorCode, resp.ReturnCode)
	}

	// Signal done and cleanup
	close(done)

	// Don't wait too long for goroutines
	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
	case <-time.After(2 * time.Second):
	}

	e.cleanup()
	return nil
}

func (e *PSExec) pipeReader(name, pipeName string, output io.Writer, done <-chan struct{}) {
	// Create new SMB connection for this pipe
	client := smb.NewClient(e.target, e.creds)
	if err := client.Connect(); err != nil {
		e.log.Debug().Msgf("Failed to connect for %s pipe: %v", name, err)
		return
	}
	defer client.Close()

	// Wait for and open pipe with read access
	pipe, err := e.waitForPipeWithClientAndAccess(client, pipeName, 50, smb.PipeAccessRead)
	if err != nil {
		e.log.Debug().Msgf("Failed to open %s pipe: %v", name, err)
		return
	}
	defer pipe.Close()

	buf := make([]byte, 1024)
	for {
		select {
		case <-done:
			return
		default:
			n, err := pipe.Read(buf)
			if err != nil {
				if err != io.EOF {
					e.log.Debug().Msgf("%s read error: %v", name, err)
				}
				return
			}
			if n > 0 {
				output.Write(buf[:n])
			}
		}
	}
}

func (e *PSExec) pipeReaderWithEchoSuppress(name, pipeName string, output io.Writer, done <-chan struct{}, lastSent chan []byte) {
	// Create new SMB connection for this pipe
	client := smb.NewClient(e.target, e.creds)
	if err := client.Connect(); err != nil {
		e.log.Debug().Msgf("Failed to connect for %s pipe: %v", name, err)
		return
	}
	defer client.Close()

	// Wait for and open pipe with read access
	pipe, err := e.waitForPipeWithClientAndAccess(client, pipeName, 50, smb.PipeAccessRead)
	if err != nil {
		e.log.Debug().Msgf("Failed to open %s pipe: %v", name, err)
		return
	}
	defer pipe.Close()

	buf := make([]byte, 1024)
	for {
		select {
		case <-done:
			return
		default:
			n, err := pipe.Read(buf)
			if err != nil {
				if err != io.EOF {
					e.log.Debug().Msgf("%s read error: %v", name, err)
				}
				return
			}
			if n > 0 {
				data := buf[:n]

				// Check if this is an echo of what we sent
				select {
				case sent := <-lastSent:
					if sent != nil && bytes.Contains(data, sent) {
						// Remove the echoed command from output
						data = bytes.Replace(data, sent, []byte{}, 1)
					}
					// Put back nil for next check
					select {
					case lastSent <- nil:
					default:
					}
				default:
				}

				if len(data) > 0 {
					output.Write(data)
				}
			}
		}
	}
}

func (e *PSExec) pipeWriter(name, pipeName string, input io.Reader, done <-chan struct{}) {
	e.pipeWriterWithEcho(name, pipeName, input, done, nil)
}

func (e *PSExec) pipeWriterWithEcho(name, pipeName string, input io.Reader, done <-chan struct{}, lastSent chan []byte) {
	// Create new SMB connection for this pipe
	client := smb.NewClient(e.target, e.creds)
	if err := client.Connect(); err != nil {
		e.log.Debug().Msgf("Failed to connect for %s pipe: %v", name, err)
		return
	}
	defer client.Close()

	// Wait for and open pipe with write access
	pipe, err := e.waitForPipeWithClientAndAccess(client, pipeName, 50, smb.PipeAccessWrite)
	if err != nil {
		e.log.Debug().Msgf("Failed to open %s pipe: %v", name, err)
		return
	}
	defer pipe.Close()

	// Create a channel for lines and a single reader goroutine
	lineChan := make(chan string)
	go func() {
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			select {
			case lineChan <- scanner.Text():
			case <-done:
				return
			}
		}
		close(lineChan)
	}()

	for {
		select {
		case <-done:
			return
		case line, ok := <-lineChan:
			if !ok {
				return
			}

			// Handle local shell escape
			if strings.HasPrefix(line, "!") {
				localCmd := strings.TrimPrefix(line, "!")
				if localCmd == "" {
					fmt.Println("[!] Usage: !command - runs command on local system")
					pipe.Write([]byte("\r\n"))
					continue
				}
				out, err := exec.Command("sh", "-c", localCmd).CombinedOutput()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[-] Local command error: %v\n", err)
				}
				fmt.Print(string(out))
				// Send empty line to get prompt back
				pipe.Write([]byte("\r\n"))
				continue
			}

			// Handle help command
			if strings.ToLower(line) == "help" {
				fmt.Println(`
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 ! {cmd}                    - executes a local shell cmd
`)
				pipe.Write([]byte("\r\n"))
				continue
			}

			// Handle lcd command
			if strings.HasPrefix(strings.ToLower(line), "lcd ") {
				path := strings.TrimPrefix(line, "lcd ")
				path = strings.TrimPrefix(path, "LCD ")
				if err := os.Chdir(path); err != nil {
					fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				} else {
					fmt.Println(path)
				}
				pipe.Write([]byte("\r\n"))
				continue
			}
			if strings.ToLower(line) == "lcd" {
				wd, _ := os.Getwd()
				fmt.Println(wd)
				pipe.Write([]byte("\r\n"))
				continue
			}

			// Record what we're sending for echo suppression
			dataToSend := []byte(line + "\r\n")
			if lastSent != nil {
				select {
				case <-lastSent: // Drain any existing value
				default:
				}
				select {
				case lastSent <- []byte(line):
				default:
				}
			}

			// Send to remote
			_, err := pipe.Write(dataToSend)
			if err != nil {
				e.log.Debug().Msgf("%s write error: %v", name, err)
				return
			}
		}
	}
}

func (e *PSExec) waitForPipe(pipeName string, maxRetries int) (io.ReadWriteCloser, error) {
	return e.waitForPipeWithClientAndAccess(e.smbClient, pipeName, maxRetries, smb.PipeAccessReadWrite)
}

func (e *PSExec) waitForPipeWithClient(client *smb.Client, pipeName string, maxRetries int) (io.ReadWriteCloser, error) {
	return e.waitForPipeWithClientAndAccess(client, pipeName, maxRetries, smb.PipeAccessReadWrite)
}

func (e *PSExec) waitForPipeWithClientAndAccess(client *smb.Client, pipeName string, maxRetries int, access smb.PipeAccess) (io.ReadWriteCloser, error) {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		pipe, err := client.OpenPipeWithAccess(pipeName, access)
		if err == nil {
			return pipe, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("pipe not ready after %d retries: %v", maxRetries, lastErr)
}

func (e *PSExec) uploadBytes(name string, data []byte) error {
	// Create a temp file approach since we don't have direct byte upload
	// Actually, let's add a method to write bytes directly

	// Get the current share's file handle
	if e.smbClient.Session == nil {
		return fmt.Errorf("session not established")
	}

	// Mount share if needed
	if err := e.smbClient.UseShare(e.share); err != nil {
		return err
	}

	// Create temp file locally, upload, then delete
	tmpFile, err := os.CreateTemp("", "psexec-upload-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	return e.smbClient.Put(tmpName, name)
}

func (e *PSExec) cleanup() {
	fmt.Printf("[*] Opening SVCManager on %s.....\n", e.target.Host)

	// Stop and delete service
	if e.createdSvc != "" {
		h, err := e.sc.OpenService(e.createdSvc, svcctl.SERVICE_ALL_ACCESS)
		if err == nil {
			fmt.Printf("[*] Stopping service %s.....\n", e.createdSvc)
			e.sc.StopService(h)
			fmt.Printf("[*] Removing service %s.....\n", e.createdSvc)
			e.sc.DeleteService(h)
			e.sc.CloseServiceHandle(h)
		}
		e.createdSvc = ""
	}

	// Delete uploaded files
	if e.share != "" {
		if err := e.smbClient.UseShare(e.share); err == nil {
			if e.uploadedBinary != "" {
				fmt.Printf("[*] Removing file %s.....\n", e.uploadedBinary)
				e.smbClient.Rm(e.uploadedBinary)
				e.uploadedBinary = ""
			}
			if e.uploadedCopy != "" {
				e.smbClient.Rm(e.uploadedCopy)
				e.uploadedCopy = ""
			}
		}
	}
}

func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// Unused but kept for reference
var _ = bytes.NewReader
