package client

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/neokofg/go-pet-vpn-client/internal/config"
	"github.com/neokofg/go-pet-vpn-client/internal/protocol"
	"github.com/songgao/water"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	ErrSkipPacket = errors.New("packet should be skipped")
)

var tapComponentIDs = []string{
	"tap0901",  // OpenVPN TAP драйвер
	"tap0801",
	"tap0401",
	"tap0201", // Новый OpenVPN TAP драйвер
}

const (
	MaxPacketSize = protocol.MaxPacketSize // Уменьшаем MTU для безопасной работы
	MinPacketSize = 20   // Минимальный размер IP пакета
)

type Client struct {
	config            *config.Config
	tcpConn           net.Conn
	udpConn           *net.UDPConn
	serverAddr        *net.UDPAddr
	tunDevice         *water.Interface
	aead              cipher.AEAD
	clientNonce       [24]byte
	serverNonce       [24]byte
	sequenceNum       uint64
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	assignedIP        net.IP
	subnetMask        net.IPMask
	oldDefaultGateway string
	ip                net.IP
	savedRoutes       []savedRoute
}

type savedRoute struct {
	network string
	netmask string
	gateway string
	metric  string
	iface   string
}

type PacketKey struct {
    ID        uint16
    Protocol  uint8
    SrcIP     string
    DstIP     string
    SrcPort   uint16
    DstPort   uint16
}

func NewClient(cfg *config.Config) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (c *Client) Start() error {
	// Подключаемся к серверу по TCP для handshake с retry механизмом
	if err := c.connectWithRetry(5); err != nil {
		return fmt.Errorf("TCP connection failed after retries: %v", err)
	}

	// Выполняем handshake
	if err := c.performHandshake(); err != nil {
		c.tcpConn.Close()
		return fmt.Errorf("handshake failed: %v", err)
	}

	// Создаем UDP соединение
	if err := c.setupUDP(); err != nil {
		c.tcpConn.Close()
		return fmt.Errorf("UDP setup failed: %v", err)
	}

	// Создаем и настраиваем TAP интерфейс
	if err := c.setupTUN(); err != nil {
		c.cleanup()
		return fmt.Errorf("TUN setup failed: %v", err)
	}

	// Настраиваем маршрутизацию
	if err := c.configureRoutes(); err != nil {
		c.cleanup()
		return fmt.Errorf("route configuration failed: %v", err)
	}

	// Проверяем соединение
	if err := c.checkConnection(); err != nil {
		log.Printf("Warning: connection test failed: %v", err)
	}

	// Запускаем обработчики пакетов
	c.wg.Add(4)
	go c.handleTunToServer()
	go c.handleUDPToTun()
	go c.keepalive()
	go c.processTUNPackets()

	return nil
}

func (c *Client) Stop() error {
	c.cancel()

	// Add timeout for graceful shutdown
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		log.Printf("VPN client stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Printf("VPN client shutdown timed out, forcing cleanup")
	}

	var errs []error

	// Clean up network routes first
	c.cleanup()

	// Close connections in correct order
	if c.udpConn != nil {
		if err := c.udpConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("UDP connection close error: %v", err))
		}
	}

	if c.tcpConn != nil {
		if err := c.tcpConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TCP connection close error: %v", err))
		}
	}

	if c.tunDevice != nil {
		if err := c.tunDevice.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TUN device close error: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple cleanup errors: %v", errs)
	}

	return nil
}

func (c *Client) cleanup() {
	if c.tunDevice == nil {
		return
	}

	// Restore saved routes
	c.restoreRoutes(c.savedRoutes)

	// Get the default gateway before closing the TUN device
	cmd := exec.Command("powershell", "-Command",
		"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop")
	output, err := cmd.Output()
	defaultGateway := strings.TrimSpace(string(output))
	
	if err == nil && defaultGateway != "" {
		// Restore the default route
		restoreCmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", defaultGateway, "metric", "1")
		restoreCmd.Run() // Ignore errors
	}

	// Reset DNS settings if needed
	cmd = exec.Command("powershell", "-Command",
		"$adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*TAP-Windows Adapter V9*' }; "+
			"if ($adapter) { Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses }")
	cmd.Run() // Ignore errors

	// Close the TUN device
	c.tunDevice.Close() // Ignore errors
	c.tunDevice = nil
}

func (c *Client) backupRoutes() ([]savedRoute, error) {
	output, err := exec.Command("route", "print").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get routing table: %v", err)
	}

	var routes []savedRoute
	lines := strings.Split(string(output), "\n")
	inIPv4Section := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Find IPv4 route table section
		if strings.Contains(line, "IPv4 Route Table") {
			inIPv4Section = true
			continue
		}
		
		// Skip until we find IPv4 section
		if !inIPv4Section {
			continue
		}
		
		// Stop when we hit the end of IPv4 section
		if strings.Contains(line, "==========") {
			break
		}

		// Skip empty lines and headers
		if line == "" || strings.Contains(line, "Active Routes:") || 
		   strings.Contains(line, "Network Destination") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 {
			route := savedRoute{
				network: fields[0],
				netmask: fields[1],
				gateway: fields[2],
			}
			if len(fields) >= 6 {
				route.iface = fields[3]
				route.metric = fields[4]
			}
			// Skip routes we're going to manage
			if route.network == "0.0.0.0" || route.network == "10.0.0.0" || 
			   route.network == c.serverAddr.IP.String() {
				continue
			}
			routes = append(routes, route)
		}
	}
	
	return routes, nil
}

func (c *Client) restoreRoutes(routes []savedRoute) {
	for _, route := range routes {
		args := []string{
			"add",
			route.network,
			"mask",
			route.netmask,
			route.gateway,
		}
		if route.metric != "" {
			args = append(args, "metric", route.metric)
		}
		if route.iface != "" {
			args = append(args, "if", route.iface)
		}
		exec.Command("route", args...).Run()
	}
}

func (c *Client) removeVPNRoutes() error {
	// Remove any existing routes that might conflict
	commands := []struct {
		args []string
		desc string
	}{
		{
			args: []string{"delete", "0.0.0.0", "mask", "0.0.0.0"},
			desc: "Removing default routes",
		},
		{
			args: []string{"delete", "10.0.0.0", "mask", "255.255.255.0"},
			desc: "Removing VPN network route",
		},
		{
			args: []string{"delete", c.serverAddr.IP.String(), "mask", "255.255.255.255"},
			desc: "Removing VPN server route",
		},
	}

	for _, cmd := range commands {
		// Повторяем удаление несколько раз, так как может быть несколько маршрутов
		for i := 0; i < 3; i++ {
			exec.Command("route", cmd.args...).Run()
		}
		log.Printf("%s...", cmd.desc)
	}

	return nil
}

func (c *Client) restoreDefaultGateway() error {
	if c.oldDefaultGateway == "" {
		return fmt.Errorf("no default gateway to restore")
	}

	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", c.oldDefaultGateway)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore default gateway: %v", err)
	}

	return nil
}

func (c *Client) connectTCP() error {
	conn, err := net.Dial("tcp", c.config.ServerAddr)
	if err != nil {
		return err
	}
	c.tcpConn = conn
	return nil
}

func (c *Client) connectWithRetry(maxAttempts int) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := c.connectTCP(); err == nil {
			log.Printf("Successfully connected on attempt %d", attempt)
			return nil
		} else {
			lastErr = err
			if attempt < maxAttempts {
				backoff := time.Duration(attempt) * time.Second
				log.Printf("Connection attempt %d failed, retrying in %v seconds: %v", attempt, backoff.Seconds(), err)
				time.Sleep(backoff)
			}
		}
	}
	return fmt.Errorf("failed to connect after %d attempts: %v", maxAttempts, lastErr)
}

func (c *Client) setupUDP() error {
	// Парсим адрес сервера
	serverHost, serverPort, err := net.SplitHostPort(c.config.ServerAddr)
	if err != nil {
		return err
	}

	// Создаем UDP адрес сервера
	// Явно указываем IPv4
	serverAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", serverHost, serverPort))
	if err != nil {
		return err
	}
	c.serverAddr = serverAddr

	// Создаем UDP соединение с явным указанием IPv4
	localAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return err
	}

	c.udpConn = conn
	log.Printf("UDP client listening on %v, server address: %v", c.udpConn.LocalAddr(), c.serverAddr)

	return nil
}

type foundAdapter struct {
	Name string
	ComponentID string
}

func findTAPAdapter() (foundAdapter, error) {
	log.Printf("Searching for TAP adapter...")

	// Open the Network registry key
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, 
		`SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`, 
		registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return foundAdapter{}, fmt.Errorf("failed to open network registry key: %v", err)
	}
	defer k.Close()

	// Read all subkeys
	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return foundAdapter{}, fmt.Errorf("failed to read network subkeys: %v", err)
	}

	// Look through each adapter
	for _, subkey := range subkeys {
		// Skip empty or special keys
		if subkey == "" || strings.HasPrefix(subkey, "Descriptions") {
			continue
		}

		// Try to open the Connection subkey
		connKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\`+subkey+`\Connection`,
			registry.READ)
		if err != nil {
			continue
		}
		defer connKey.Close()

		// Get the adapter name
		name, _, err := connKey.GetStringValue("Name")
		if err != nil {
			continue
		}

		// Check if this is a TAP adapter by looking up its ComponentId in the Class key
		classKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`,
			registry.READ)
		if err != nil {
			continue
		}
		defer classKey.Close()

		// Read class subkeys
		classSubkeys, err := classKey.ReadSubKeyNames(-1)
		if err != nil {
			continue
		}

		// Look for matching NetCfgInstanceId
		for _, classSubkey := range classSubkeys {
			adapterKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
				`SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\`+classSubkey,
				registry.READ)
			if err != nil {
				continue
			}
			defer adapterKey.Close()

			// Get NetCfgInstanceId
			instanceId, _, err := adapterKey.GetStringValue("NetCfgInstanceId")
			if err != nil || instanceId != subkey {
				continue
			}

			// Check ComponentId
			componentId, _, err := adapterKey.GetStringValue("ComponentId")
			if err != nil {
				continue
			}

			// Check if this is a TAP adapter
			for _, id := range tapComponentIDs {
				if strings.EqualFold(componentId, id) {
					log.Printf("Found TAP adapter in registry: %s (ComponentId: %s)", name, componentId)
					return foundAdapter{Name: name, ComponentID: componentId}, nil
				}
			}
		}
	}

	return foundAdapter{}, fmt.Errorf("no TAP adapter found in registry")
}

func (c *Client) setupTUN() error {
	log.Printf("Setting up TUN device...")

	// Ищем TAP адаптер
	adapter, err := findTAPAdapter()
	if err != nil {
		return fmt.Errorf("failed to find TAP adapter: %v", err)
	}

	log.Printf("Using TAP adapter: %q", adapter.Name)

	// Create TAP device configuration
	config := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: adapter.ComponentID,
			Network: "10.0.0.0/24",
			InterfaceName: adapter.Name,
		},
	}

	// Create TAP device
	c.tunDevice, err = water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create TAP device: %v", err)
	}

	// Enable the interface and set IP address
	cmd := exec.Command("powershell", "-Command", `
		$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
		$adapter = Get-NetAdapter | Where-Object { $_.Name -eq '`+adapter.Name+`' }
		if ($adapter.Status -ne 'Up') {
			Enable-NetAdapter -Name '`+adapter.Name+`' -Confirm:$false
		}
		Remove-NetIPAddress -InterfaceAlias '`+adapter.Name+`' -Confirm:$false -ErrorAction SilentlyContinue
		New-NetIPAddress -InterfaceAlias '`+adapter.Name+`' -IPAddress '`+c.assignedIP.String()+`' -PrefixLength 24 -Confirm:$false
	`)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure TAP interface: %v (output: %s)", err, string(output))
	}

	return nil
}

func (c *Client) performHandshake() error {
	// Генерируем nonce
	if _, err := rand.Read(c.clientNonce[:]); err != nil {
		return err
	}

	// Создаем handshake пакет
	handshake := &protocol.HandshakePacket{
		ClientNonce: c.clientNonce,
	}
	copy(handshake.Token[:], []byte(c.config.Token))

	// Отправляем handshake
	header := &protocol.PacketHeader{
		Version:     protocol.ProtocolVersion,
		Type:        protocol.PacketTypeHandshake,
		SequenceNum: 0,
		PayloadSize: uint32(len(handshake.Marshal())),
	}

	// Отправляем header и handshake
	if _, err := c.tcpConn.Write(append(header.Marshal(), handshake.Marshal()...)); err != nil {
		return err
	}

	// Читаем ответ
	buf := make([]byte, protocol.HeaderSize+66) // Размер заголовка + размер ответа
	if _, err := c.tcpConn.Read(buf); err != nil {
		return err
	}

	// Разбираем ответ
	response, err := protocol.UnmarshalHandshakeResponse(buf[protocol.HeaderSize:])
	if err != nil {
		return err
	}

	// Сохраняем данные
	c.serverNonce = response.ServerNonce
	c.assignedIP = net.IP(response.AssignedIP[:])
	c.subnetMask = net.IPMask(response.SubnetMask[:])
	c.ip = c.assignedIP

	if c.assignedIP[len(c.assignedIP)-1] == 0 {
		return fmt.Errorf("received invalid IP address: %s", c.assignedIP)
	}

	// Создаем AEAD cipher
	c.aead, err = chacha20poly1305.New(response.Key[:])
	if err != nil {
		return err
	}

	log.Printf("Handshake completed. Assigned IP: %s/%d",
		c.assignedIP, net.IPMask(response.SubnetMask[:]))

	return nil
}

func (c *Client) configureRoutes() error {
	log.Printf("Configuring routes...")

	// Get the TAP adapter index and interface alias
	cmd := exec.Command("powershell", "-Command", 
		`Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*TAP-Windows Adapter V9*' } | Select-Object -ExpandProperty ifIndex`)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get TAP adapter index: %v", err)
	}

	cmd = exec.Command("powershell", "-Command", 
		`Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*TAP-Windows Adapter V9*' } | Select-Object -ExpandProperty InterfaceAlias`)
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get TAP adapter alias: %v", err)
	}
	tapAlias := strings.TrimSpace(string(output))

	// Get the physical adapter index and interface alias
	cmd = exec.Command("powershell", "-Command", 
		`Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Intel*Wi-Fi*' } | Select-Object -ExpandProperty ifIndex`)
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get physical adapter index: %v", err)
	}

	cmd = exec.Command("powershell", "-Command", 
		`Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Intel*Wi-Fi*' } | Select-Object -ExpandProperty InterfaceAlias`)
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get physical adapter alias: %v", err)
	}
	physicalAlias := strings.TrimSpace(string(output))

	// Get the default gateway
	cmd = exec.Command("powershell", "-Command", 
		`Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1 -ExpandProperty NextHop`)
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}
	c.oldDefaultGateway = strings.TrimSpace(string(output))

	// Remove existing routes using PowerShell
	removeCommands := []string{
		// Remove VPN server route
		fmt.Sprintf(`Remove-NetRoute -DestinationPrefix "%s/32" -Confirm:$false -ErrorAction SilentlyContinue`, c.serverAddr.IP.String()),
		// Remove VPN network route
		`Remove-NetRoute -DestinationPrefix "10.0.0.0/24" -Confirm:$false -ErrorAction SilentlyContinue`,
		// Remove default routes with low metrics
		`Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.RouteMetric -le 100 } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`,
		// Remove existing backup route
		fmt.Sprintf(`Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.InterfaceAlias -eq "%s" -and $_.NextHop -eq "%s" } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, physicalAlias, c.oldDefaultGateway),
		// Remove any persistent routes in the VPN subnet
		`Remove-NetRoute -DestinationPrefix "10.0.0.0/24" -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue`,
	}

	for _, cmd := range removeCommands {
		exec.Command("powershell", "-Command", cmd).Run()
	}

	// Wait for routes to stabilize
	time.Sleep(2 * time.Second)

	// Check and remove any remaining conflicting routes
	checkRouteCommands := []string{
		`Get-NetRoute -DestinationPrefix "10.0.0.0/24" -ErrorAction SilentlyContinue | ForEach-Object { Remove-NetRoute -DestinationPrefix $_.DestinationPrefix -InterfaceIndex $_.InterfaceIndex -NextHop $_.NextHop -Confirm:$false -ErrorAction SilentlyContinue }`,
		fmt.Sprintf(`Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.InterfaceAlias -eq "%s" } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, physicalAlias),
	}

	for _, cmd := range checkRouteCommands {
		exec.Command("powershell", "-Command", cmd).Run()
	}

	// Wait again for routes to stabilize
	time.Sleep(time.Second)

	// Add routes using PowerShell
	addCommands := []struct {
		cmd  string
		desc string
	}{
		{
			// Add VPN server route through physical adapter
			cmd: fmt.Sprintf(`New-NetRoute -DestinationPrefix "%s/32" -InterfaceAlias "%s" -NextHop "%s" -RouteMetric 1 -PolicyStore ActiveStore`,
				c.serverAddr.IP.String(), physicalAlias, c.oldDefaultGateway),
			desc: "Adding VPN server route",
		},
		{
			// Add VPN network route through TAP adapter
			cmd: fmt.Sprintf(`New-NetRoute -DestinationPrefix "10.0.0.0/24" -InterfaceAlias "%s" -NextHop "%s" -RouteMetric 1 -PolicyStore ActiveStore`,
				tapAlias, c.assignedIP.String()),
			desc: "Adding VPN network route",
		},
		{
			// Add default route through VPN
			cmd: fmt.Sprintf(`New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias "%s" -NextHop "%s" -RouteMetric 1 -PolicyStore ActiveStore`,
				tapAlias, c.assignedIP.String()),
			desc: "Adding default route through VPN",
		},
		{
			// Add backup default route through physical adapter with higher metric
			cmd: fmt.Sprintf(`New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias "%s" -NextHop "%s" -RouteMetric 2000 -PolicyStore ActiveStore -ErrorAction SilentlyContinue`,
				physicalAlias, c.oldDefaultGateway),
			desc: "Adding backup default route through physical adapter",
		},
	}

	// Add routes with retries
	for _, cmd := range addCommands {
		var success bool
		for i := 0; i < 3; i++ {
			output, err := exec.Command("powershell", "-Command", cmd.cmd).CombinedOutput()
			if err == nil {
				success = true
				log.Printf("%s... OK", cmd.desc)

				// Also add to persistent store
				persistentCmd := strings.Replace(cmd.cmd, "ActiveStore", "PersistentStore", 1)
				exec.Command("powershell", "-Command", persistentCmd).Run()
				break
			}
			log.Printf("Attempt %d: %s failed: %v (%s)", i+1, cmd.desc, err, string(output))
			time.Sleep(time.Second)
		}
		if !success {
			return fmt.Errorf("failed to %s after 3 attempts", cmd.desc)
		}
	}

	// Verify the routes
	if !c.verifyRoutes() {
		return fmt.Errorf("route verification failed")
	}

	return nil
}

func (c *Client) verifyRoutes() bool {
	log.Printf("Starting route verification...")
	
	output, err := exec.Command("route", "print").CombinedOutput()
	if err != nil {
		log.Printf("Failed to get routing table: %v", err)
		return false
	}

	routeTable := string(output)
	log.Printf("Current routing table:\n%s", routeTable)

	// Check for required routes
	requiredRoutes := []struct {
		network string
		gateway string
		desc    string
	}{
		{c.serverAddr.IP.String(), c.oldDefaultGateway, "VPN server route"},
		{"10.0.0.0", c.assignedIP.String(), "VPN network route"},
		{"0.0.0.0", c.assignedIP.String(), "Default VPN route"},
	}

	for _, route := range requiredRoutes {
		// Look for the route in both active and persistent routes sections
		found := false
		lines := strings.Split(routeTable, "\n")
		for _, line := range lines {
			// Skip empty lines and headers
			if len(strings.TrimSpace(line)) == 0 || strings.Contains(line, "==") {
				continue
			}
			
			// Check if line contains both network and gateway
			if strings.Contains(line, route.network) && strings.Contains(line, route.gateway) {
				found = true
				log.Printf("Found required route: %s (network=%s, gateway=%s)", 
					route.desc, route.network, route.gateway)
				break
			}
		}
		
		if !found {
			log.Printf("Missing required route: %s (network=%s, gateway=%s)", 
				route.desc, route.network, route.gateway)
			return false
		}
	}

	log.Printf("All required routes verified successfully")
	return true
}

func (c *Client) checkDNS() error {
	cmd := exec.Command("nslookup", "google.com", "8.8.8.8")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("DNS check failed: %v, output: %s", err, output)
	}
	return nil
}

func (c *Client) checkConnection() error {
	// Даем время на применение настроек
	time.Sleep(3 * time.Second)

	// Сначала проверяем связь с VPN сервером через Wi-Fi
	serverHost, _, _ := net.SplitHostPort(c.config.ServerAddr)
	cmd := exec.Command("ping", "-n", "1", "-w", "3000", serverHost)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("VPN server ping failed: %v, output: %s", err, output)

		// 2. Проверяем состояние TAP интерфейса
		cmd = exec.Command("powershell", "-Command", `
			$tap = Get-NetAdapter | Where-Object { $_.Name -eq '`+c.config.TunName+`' }
			Write-Host "Status: $($tap.Status)"
			Write-Host "Link Speed: $($tap.LinkSpeed)"
			Write-Host "Media Status: $($tap.MediaConnectionState)"
		`)

		output, err = cmd.CombinedOutput()
		if err == nil {
			log.Printf("TAP interface status:\n%s", output)
		}

		// 3. Проверяем маршруты до VPN шлюза
		cmd = exec.Command("tracert", "-d", "-h", "5", "10.0.0.1")
		if output, err := cmd.CombinedOutput(); err == nil {
			log.Printf("Route to VPN gateway:\n%s", output)
		}

		return fmt.Errorf("VPN tunnel not working")
	}

	log.Printf("VPN tunnel is working")
	return nil
}

func CheckAdminPrivileges() error {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return fmt.Errorf("failed to initialize sid: %v", err)
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return fmt.Errorf("failed to check membership: %v", err)
	}
	if !member {
		return fmt.Errorf("this program must be run as administrator")
	}
	return nil
}

func (c *Client) recalculateChecksums(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short for IP header")
	}

	// Recalculate IP header checksum
	c.recalculateIPChecksum(packet)

	// Get IP header length
	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl {
		return fmt.Errorf("packet too short for declared IP header length")
	}

	protocol := packet[9]
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	length := binary.BigEndian.Uint16(packet[2:4])

	var srcPort, dstPort uint16
	if protocol == 17 && len(packet) >= 28 { // UDP
		srcPort = binary.BigEndian.Uint16(packet[20:22])
		dstPort = binary.BigEndian.Uint16(packet[22:24])
	}

	log.Printf("[DEBUG] Processing IPv4 packet: Protocol=%d, Src=%s:%d, Dst=%s:%d, Length=%d",
		protocol, srcIP, srcPort, dstIP, dstPort, length)

	return nil
}

func (c *Client) handleTunToServer() {
	c.wg.Add(1)
	defer c.wg.Done()

	log.Printf("Starting TUN to Server handler with assigned IP: %v, subnet mask: %v", c.assignedIP, c.subnetMask)

	buffer := make([]byte, MaxPacketSize)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			n, err := c.tunDevice.Read(buffer)
			if err != nil {
				if c.ctx.Err() != nil {
					return
				}
				log.Printf("Error reading from TUN: %v", err)
				continue
			}

			packet := buffer[:n]
			if len(packet) < 14 {
				log.Printf("[DEBUG] Packet too short for Ethernet frame: %d bytes", len(packet))
				continue
			}

			etherType := binary.BigEndian.Uint16(packet[12:14])

			switch etherType {
			case 0x0800: // IPv4
				ipPacket := packet[14:] // Пропускаем Ethernet заголовок
				if len(ipPacket) < 20 {
					log.Printf("[DEBUG] IP packet too short: %d bytes", len(ipPacket))
					continue
				}

				// Получаем базовую информацию о пакете для логирования
				id := binary.BigEndian.Uint16(ipPacket[4:6])
				protocol := ipPacket[9]
				srcIP := net.IP(ipPacket[12:16])
				dstIP := net.IP(ipPacket[16:20])

				log.Printf("[DEBUG] Processing IPv4 packet - ID=%d, Protocol=%d, Src=%s, Dst=%s",
					id, protocol, srcIP, dstIP)

				// Skip multicast packets
				if dstIP[0] >= 224 && dstIP[0] <= 239 {
					log.Printf("[DEBUG] Skipping multicast packet: %s", dstIP)
					continue
				}

				// Skip packets from our IP to prevent loops
				if bytes.Equal(srcIP, c.assignedIP) {
					log.Printf("[DEBUG] Skipping packet from our IP to prevent loops: %s", srcIP)
					continue
				}

				// Если это broadcast пакет, меняем адрес на VPN сервер
				if dstIP[len(dstIP)-1] == 255 {
					log.Printf("[DEBUG] Converting broadcast packet %s -> 10.0.0.1", dstIP)
					copy(ipPacket[16:20], net.ParseIP("10.0.0.1").To4())
					c.recalculateIPChecksum(ipPacket)
					dstIP = net.IP(ipPacket[16:20])
					log.Printf("[DEBUG] After conversion: New destination IP=%s", dstIP)
				}

				// Проверяем, что адрес назначения в VPN подсети
				if !c.isInVPNSubnet(dstIP) {
					log.Printf("[DEBUG] Skipping packet to non-VPN IP: %s", dstIP)
					continue
				}

				if err := c.handleIPv4Packet(ipPacket); err != nil {
					if err == ErrSkipPacket {
						continue
					}
					log.Printf("[DEBUG] Error handling IPv4 packet: %v", err)
					continue
				}

				// Отправляем пакет на сервер
				if err := c.sendPacketToServer(ipPacket); err != nil {
					log.Printf("[DEBUG] Error sending packet to server: %v", err)
					continue
				}

				log.Printf("[DEBUG] Successfully sent packet to server: ID=%d, Protocol=%d, Src=%s, Dst=%s",
					id, protocol, srcIP, dstIP)

			case 0x0806: // ARP
				arpPacket := packet[14:]
				if err := c.handleARPPacket(arpPacket); err != nil {
					if err == ErrSkipPacket {
						continue
					}
					log.Printf("[DEBUG] Error handling ARP packet: %v", err)
					continue
				}

				// Отправляем ARP пакет только если он для VPN подсети
				targetIP := net.IP(arpPacket[24:28]) // Target Protocol Address
				if !c.isInVPNSubnet(targetIP) {
					log.Printf("[DEBUG] Skipping ARP for non-VPN IP: %s", targetIP)
					continue
				}

				// Отправляем пакет на сервер
				if err := c.sendPacketToServer(packet[14:]); err != nil {
					log.Printf("[DEBUG] Error sending ARP packet to server: %v", err)
					continue
				}

				log.Printf("[DEBUG] Successfully sent ARP packet to server for target IP: %s", targetIP)

			default:
				log.Printf("[DEBUG] Skipping non-IPv4/ARP packet: EtherType=0x%04x", etherType)
				continue
			}
		}
	}
}

func (c *Client) handleIPv4Packet(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("IPv4 packet too short: %d bytes", len(packet))
	}

	version := packet[0] >> 4
	if version != 4 {
		return fmt.Errorf("not an IPv4 packet: version=%d", version)
	}

	protocol := packet[9]
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	id := binary.BigEndian.Uint16(packet[4:6])
	totalLength := binary.BigEndian.Uint16(packet[2:4])

	var srcPort, dstPort uint16
	if protocol == 17 && len(packet) >= 28 { // UDP
		srcPort = binary.BigEndian.Uint16(packet[20:22])
		dstPort = binary.BigEndian.Uint16(packet[22:24])
	}

	log.Printf("[DEBUG] Processing IPv4 packet - ID=%d, Protocol=%d, Src=%s:%d, Dst=%s:%d, Length=%d",
		id, protocol, srcIP, srcPort, dstIP, dstPort, totalLength)

	return nil
}

func (c *Client) handleUDPToTun() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in handleUDPToTun: %v", r)
		}
	}()

	buffer := make([]byte, MaxPacketSize)
	ethHeader := make([]byte, 14)

	// Формируем Ethernet заголовок
	// Destination MAC (broadcast)
	copy(ethHeader[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Source MAC (не важно, можно использовать любой)
	copy(ethHeader[6:12], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// EtherType (IPv4)
	ethHeader[12] = 0x08
	ethHeader[13] = 0x00

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			n, remoteAddr, err := c.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if c.ctx.Err() != nil {
					return
				}
				log.Printf("Error reading from UDP: %v", err)
				continue
			}

			log.Printf("Received %d bytes from UDP %s", n, remoteAddr.String())

			if n < protocol.HeaderSize {
				log.Printf("Received packet too small: %d bytes", n)
				continue
			}

			header, err := protocol.UnmarshalHeader(buffer[:protocol.HeaderSize])
			if err != nil {
				log.Printf("Error parsing header: %v", err)
				continue
			}

			log.Printf("Received packet type %d, sequence %d, payload size %d", 
				header.Type, header.SequenceNum, header.PayloadSize)

			switch header.Type {
			case protocol.PacketTypeData:
				if uint32(n) < protocol.HeaderSize+header.PayloadSize {
					log.Printf("Data packet too small: expected %d, got %d",
						protocol.HeaderSize+header.PayloadSize, n)
					continue
				}

				encryptedData := buffer[protocol.HeaderSize:n]
				log.Printf("Encrypted data size: %d bytes", len(encryptedData))

				// Создаем nonce из ServerNonce и SequenceNum
				nonce := make([]byte, chacha20poly1305.NonceSize)
				copy(nonce, c.serverNonce[:])
				binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

				// Расшифровываем данные
				decrypted, err := c.aead.Open(nil, nonce, encryptedData, nil)
				if err != nil {
					log.Printf("Error decrypting data: %v", err)
					continue
				}

				log.Printf("Decrypted data size: %d bytes", len(decrypted))

				// Проверяем IP пакет
				if len(decrypted) < 20 {
					log.Printf("Decrypted packet too short: %d bytes", len(decrypted))
					continue
				}

				version := decrypted[0] >> 4
				if version != 4 {
					log.Printf("Invalid IP version: %d", version)
					continue
				}

				protocol := decrypted[9]
				srcIP := net.IP(decrypted[12:16])
				dstIP := net.IP(decrypted[16:20])
				length := binary.BigEndian.Uint16(decrypted[2:4])

				log.Printf("Received IP packet: Protocol=%d, Src=%s, Dst=%s, Length=%d",
					protocol, srcIP, dstIP, length)

				// Создаем полный Ethernet фрейм
				fullPacket := make([]byte, len(ethHeader)+len(decrypted))
				copy(fullPacket[:14], ethHeader)
				copy(fullPacket[14:], decrypted)

				// Записываем в TAP интерфейс
				written, err := c.tunDevice.Write(fullPacket)
				if err != nil {
					log.Printf("Error writing to TAP: %v", err)
					continue
				}
				log.Printf("Successfully wrote %d bytes to TAP device", written)

			case protocol.PacketTypeKeepalive:
				log.Printf("Received keepalive packet")

			case protocol.PacketTypeDisconnect:
				log.Printf("Received disconnect packet")
				c.cancel()
				return

			default:
				log.Printf("Unknown packet type: %d", header.Type)
			}
		}
	}
}

func (c *Client) keepalive() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second * protocol.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			header := &protocol.PacketHeader{
				Version:     protocol.ProtocolVersion,
				Type:        protocol.PacketTypeKeepalive,
				SequenceNum: c.sequenceNum,
			}
			c.sequenceNum++

			if _, err := c.udpConn.WriteToUDP(header.Marshal(), c.serverAddr); err != nil {
				log.Printf("Failed to send keepalive: %v", err)
			}
		}
	}
}

type Route struct {
	Network   net.IPNet
	Gateway   net.IP
	Interface string
}

func logRoutes() {
	cmd := exec.Command("route", "print")
	if output, err := cmd.CombinedOutput(); err == nil {
		log.Printf("Current routes:\n%s", string(output))
	}
}

func (c *Client) processTUNPackets() {
	defer c.wg.Done()
	buffer := make([]byte, 2048)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			n, err := c.tunDevice.Read(buffer)
			if err != nil {
				if c.ctx.Err() == nil {
					log.Printf("Error reading from TUN: %v", err)
				}
				continue
			}

			packet := buffer[:n]
			log.Printf("Read %d bytes from TUN", len(packet))

			// Handle the packet
			if err := c.handleTUNPacket(packet); err != nil {
				if err == ErrSkipPacket {
					continue
				}
				log.Printf("Error handling packet: %v", err)
				continue
			}

			// Send packet to server
			log.Printf("Sending packet to server: size=%d", len(packet))
			if err := c.sendPacketToServer(packet); err != nil {
				log.Printf("Error sending packet to server: %v", err)
			} else {
				log.Printf("Successfully sent packet to server")
			}
		}
	}
}

func (c *Client) sendPacketToServer(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Проверяем тип пакета и адрес назначения
	dstIP := net.IP(packet[16:20])
	
	// Не отправляем multicast пакеты
	if dstIP[0] >= 224 && dstIP[0] <= 239 {
		log.Printf("[DEBUG] Not sending multicast packet to server: %s", dstIP)
		return nil
	}

	// Не отправляем пакеты вне VPN подсети
	if !c.isInVPNSubnet(dstIP) {
		log.Printf("[DEBUG] Not sending packet to non-VPN IP: %s", dstIP)
		return nil
	}

	log.Printf("[DEBUG] Sending packet to server: size=%d", len(packet))

	// Создаем заголовок пакета
	header := &protocol.PacketHeader{
		Version:     protocol.ProtocolVersion,
		Type:        protocol.PacketTypeData,
		SequenceNum: c.sequenceNum,
		PayloadSize: uint32(len(packet)),
	}
	c.sequenceNum++

	// Создаем nonce для шифрования
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, c.clientNonce[:])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

	// Шифруем данные
	encrypted := c.aead.Seal(nil, nonce, packet, nil)
	
	// Формируем полный пакет
	fullPacket := append(header.Marshal(), encrypted...)
	
	log.Printf("Sending packet to server: header_size=%d, encrypted_size=%d, total_size=%d, server_addr=%v",
		len(header.Marshal()), len(encrypted), len(fullPacket), c.serverAddr)

	// Отправляем пакет
	n, err := c.udpConn.WriteToUDP(fullPacket, c.serverAddr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}
	
	log.Printf("Successfully sent %d bytes to server %v", n, c.serverAddr)
	return nil
}

func (c *Client) handleTUNPacket(packet []byte) error {
	if len(packet) < 1 {
		return fmt.Errorf("packet too small")
	}

	// Check if this is an Ethernet frame
	if len(packet) >= 14 {
		etherType := binary.BigEndian.Uint16(packet[12:14])
		log.Printf("Received Ethernet frame: Type=0x%04x, Length=%d", etherType, len(packet))

		switch etherType {
		case 0x0800: // IPv4
			return c.handleIPv4Packet(packet[14:])
		case 0x0806: // ARP
			return c.handleARPPacket(packet[14:])
		case 0x86DD: // IPv6
			log.Printf("IPv6 not supported yet")
			return nil
		default:
			log.Printf("Unknown EtherType: 0x%04x", etherType)
			return nil
		}
	}

	// If not an Ethernet frame, try to process as raw IP packet
	version := packet[0] >> 4
	if version == 4 {
		return c.handleIPv4Packet(packet)
	}

	return fmt.Errorf("unsupported packet version: %d", version)
}

func (c *Client) handleARPPacket(packet []byte) error {
	if len(packet) < 28 {
		return fmt.Errorf("ARP packet too short: %d bytes", len(packet))
	}

	// Разбираем ARP пакет
	hwType := binary.BigEndian.Uint16(packet[0:2])
	protoType := binary.BigEndian.Uint16(packet[2:4])
	hwSize := packet[4]
	protoSize := packet[5]
	op := binary.BigEndian.Uint16(packet[6:8])
	senderIP := net.IP(packet[14:18])
	targetIP := net.IP(packet[24:28])

	log.Printf("ARP packet: HWType=%d, ProtoType=0x%04x, HWSize=%d, ProtoSize=%d, Op=%d, Sender=%s, Target=%s",
		hwType, protoType, hwSize, protoSize, op, senderIP, targetIP)

	// Проверяем, что это IPv4 ARP
	if protoType != 0x0800 {
		log.Printf("Ignoring non-IPv4 ARP packet: 0x%04x", protoType)
		return ErrSkipPacket
	}

	// Проверяем, что целевой IP в нашей VPN подсети
	if !c.isInVPNSubnet(targetIP) {
		log.Printf("Ignoring ARP request for non-VPN IP: %s", targetIP)
		return ErrSkipPacket
	}

	return nil
}

func (c *Client) isInVPNSubnet(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip[0] == 10 && ip[1] == 0 && ip[2] == 0 && ip[3] <= 255
}

func (c *Client) isValidVPNAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check if this is IPv4
	ip = ip.To4()
	if ip == nil {
		return false
	}

	// Check VPN range (10.0.0.0/24)
	if ip[0] != 10 || ip[1] != 0 || ip[2] != 0 {
		return false
	}

	// Allow broadcast address (255) but not zero address
	if ip[3] == 0 {
		return false
	}

	return true
}

func (c *Client) isValidDestination(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return false
	}

	// Check if this is a valid IPv4 address
	ip = ip.To4()
	if ip == nil {
		return false
	}

	// Check special ranges
	if ip[0] == 0 || ip[0] == 127 || ip[0] == 169 && ip[1] == 254 {
		return false
	}

	return true
}

func (c *Client) recalculateIPChecksum(packet []byte) {
	// Reset current checksum
	packet[10] = 0
	packet[11] = 0

	// Calculate new checksum
	var sum uint32
	for i := 0; i < len(packet)-1; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if len(packet)%2 == 1 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	checksum := ^uint16(sum)
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)
}

func (c *Client) testTunnel() error {
	log.Printf("Testing VPN tunnel...")

	// 1. Try to ping the VPN gateway
	cmd := exec.Command("ping", "-n", "1", "-w", "3000", "10.0.0.1")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("VPN gateway ping failed: %v, output: %s", err, output)

		// 2. Check the TAP interface status
		cmd = exec.Command("powershell", "-Command", `
			$tap = Get-NetAdapter | Where-Object { $_.Name -eq '`+c.config.TunName+`' }
			Write-Host "Status: $($tap.Status)"
			Write-Host "Link Speed: $($tap.LinkSpeed)"
			Write-Host "Media Status: $($tap.MediaConnectionState)"
		`)

		output, err = cmd.CombinedOutput()
		if err == nil {
			log.Printf("TAP interface status:\n%s", output)
		}

		// 3. Check the routes to the VPN gateway
		cmd = exec.Command("tracert", "-d", "-h", "5", "10.0.0.1")
		if output, err := cmd.CombinedOutput(); err == nil {
			log.Printf("Route to VPN gateway:\n%s", output)
		}

		return fmt.Errorf("VPN tunnel not working")
	}

	log.Printf("VPN tunnel is working")
	return nil
}

func getDefaultRouteWindows() (*Route, error) {
	cmd := exec.Command("powershell", "-Command", `
		$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
		$defaultRoute = Get-NetRoute | Where-Object { 
			$_.DestinationPrefix -eq '0.0.0.0/0' -and 
			$_.NextHop -ne '0.0.0.0' -and 
			$_.NextHop -ne '::'
		} | Sort-Object -Property RouteMetric |
		Select-Object -First 1;

		if ($defaultRoute) {
			$interface = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
			@{
				"Gateway" = $defaultRoute.NextHop
				"InterfaceIndex" = $interface.ifIndex
				"InterfaceName" = $interface.Name
				"Metric" = $defaultRoute.RouteMetric
			} | ConvertTo-Json
		} else {
			# Fallback to using route print
			$routePrint = route print 0.0.0.0
			$gateway = ($routePrint | Select-String -Pattern '\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)').Matches.Groups[1].Value
			$interface = Get-NetAdapter | 
			Where-Object { $_.Status -eq 'Up' -and $_.MediaType -eq '802.3' } | Select-Object -First 1

			@{
				"Gateway" = $gateway
				"InterfaceIndex" = if ($interface) { $interface.ifIndex } else { 1 }
				"InterfaceName" = if ($interface) { $interface.Name } else { "Unknown" }
				"Metric" = 0
			} | ConvertTo-Json
		}
	`)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get default gateway info: %v", err)
	}

	var result struct {
		Gateway       string `json:"Gateway"`
		InterfaceIndex int    `json:"InterfaceIndex"`
		InterfaceName string `json:"InterfaceName"`
		Metric       int    `json:"Metric"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		log.Printf("Default route info command output: %s", string(output))
		return nil, fmt.Errorf("failed to parse default gateway info: %v", err)
	}

	if result.Gateway == "" {
		return nil, fmt.Errorf("could not determine default gateway")
	}

	// Convert interface name from UTF-16 to UTF-8 if needed
	interfaceName := result.InterfaceName
	if strings.Contains(interfaceName, "\uFFFD") {
		// Try to get interface name using netsh
		cmd = exec.Command("netsh", "interface", "show", "interface")
		output, err = cmd.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, fmt.Sprintf("%d", result.InterfaceIndex)) {
					fields := strings.Fields(line)
					if len(fields) >= 4 {
						interfaceName = strings.Join(fields[3:], " ")
						break
					}
				}
			}
		}
	}

	return &Route{
		Gateway:   net.ParseIP(result.Gateway),
		Interface: interfaceName,
	}, nil
}

func (c *Client) min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func calculateIPChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}
