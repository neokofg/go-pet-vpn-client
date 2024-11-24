package client

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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

var tapComponentIDs = []string{
	"tap",
	"tap0901", // Старый OpenVPN TAP драйвер
	"tap0801",
	"tap0601",
	"tap0401",
	"tap0201", // Новый OpenVPN TAP драйвер
}

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
	// Подключаемся к серверу по TCP для handshake
	if err := c.connectTCP(); err != nil {
		return fmt.Errorf("TCP connection failed: %v", err)
	}
	defer c.tcpConn.Close()

	// Выполняем handshake
	if err := c.performHandshake(); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	// Создаем UDP соединение
	if err := c.setupUDP(); err != nil {
		return fmt.Errorf("UDP setup failed: %v", err)
	}
	defer c.udpConn.Close()

	// Создаем и настраиваем TUN интерфейс
	if err := c.setupTUN(); err != nil {
		return fmt.Errorf("TUN setup failed: %v", err)
	}
	defer c.tunDevice.Close()

	// Настраиваем маршрутизацию
	if err := c.configureRoutes(); err != nil {
		return fmt.Errorf("route configuration failed: %v", err)
	}

	// Проверяем соединение
	if err := c.checkConnection(); err != nil {
		log.Printf("Warning: connection test failed: %v", err)
		// Не прерываем работу, но логируем проблему
	}

	// Запускаем обработчики пакетов
	c.wg.Add(4)
	go c.handleTunToUDP()
	go c.handleUDPToTun()
	go c.keepalive()
	go c.processTUNPackets()

	// Ждем завершения
	<-c.ctx.Done()
	c.wg.Wait()
	return nil
}

func (c *Client) Stop() error {
	c.cancel()

	if c.tcpConn != nil {
		c.tcpConn.Close()
	}

	if c.udpConn != nil {
		c.udpConn.Close()
	}

	// Очищаем маршруты перед закрытием TUN
	if err := c.cleanup(); err != nil {
		log.Printf("Error during cleanup: %v", err)
	}

	if c.tunDevice != nil {
		c.tunDevice.Close()
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

func (c *Client) setupUDP() error {
	// Парсим адрес сервера
	serverHost, _, err := net.SplitHostPort(c.config.ServerAddr)
	if err != nil {
		return err
	}

	// Создаем UDP адрес сервера
	c.serverAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:8001", serverHost))
	if err != nil {
		return err
	}

	// Создаем UDP соединение
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	c.udpConn = conn

	return nil
}

func findTAPAdapter() (string, error) {
	log.Println("Searching for TAP adapter...")

	// Используем PowerShell для получения имени интерфейса TAP адаптера
	cmd := exec.Command("powershell", "-Command", `
        Get-NetAdapter | 
        Where-Object { $_.InterfaceDescription -like '*TAP-Windows Adapter V9*' } |
        Select-Object -First 1 -ExpandProperty Name
    `)

	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		name := strings.TrimSpace(string(output))
		if name != "" {
			log.Printf("Found TAP adapter: %s", name)
			return name, nil
		}
	}

	// Если не нашли через PowerShell - возвращаем стандартное имя
	defaultName := "Подключение по локальной сети"
	log.Printf("Using default TAP adapter name: %s", defaultName)
	return defaultName, nil
}

func checkTAPDriver() error {
	log.Println("Checking TAP driver through registry...")
	if err := checkTAPInRegistry(); err == nil {
		log.Println("TAP driver found in registry")
		return nil
	} else {
		log.Printf("Registry check failed: %v", err)
	}

	log.Println("Checking TAP driver through netsh...")
	if err := checkTAPWithNetsh(); err == nil {
		log.Println("TAP driver found through netsh")
		return nil
	} else {
		log.Printf("Netsh check failed: %v", err)
	}

	return fmt.Errorf("TAP driver not found after all checks")
}

func checkTAPInRegistry() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`,
		registry.READ)
	if err != nil {
		return err
	}
	defer k.Close()

	// Читаем все подключи
	subKeys, err := k.ReadSubKeyNames(-1) // -1 читает все ключи
	if err != nil {
		return err
	}

	for _, subKeyName := range subKeys {
		subKey, err := registry.OpenKey(k, subKeyName, registry.READ)
		if err != nil {
			continue
		}
		defer subKey.Close()

		// Проверяем ComponentId
		componentId, _, err := subKey.GetStringValue("ComponentId")
		if err != nil {
			continue
		}

		// Проверяем различные известные TAP идентификаторы
		for _, tapId := range []string{"tap0901", "tap0801", "tap", "tap-windows6"} {
			if strings.EqualFold(componentId, tapId) {
				return nil
			}
		}
	}
	return fmt.Errorf("TAP adapter not found in registry")
}

func checkTAPWithNetsh() error {
	cmd := exec.Command("netsh", "interface", "show", "interface")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// Ищем любой TAP адаптер в выводе
	outputStr := strings.ToLower(string(output))
	if strings.Contains(outputStr, "tap") ||
		strings.Contains(outputStr, "openvpn") ||
		strings.Contains(outputStr, "virtual") {
		return nil
	}

	return fmt.Errorf("TAP adapter not found in netsh output")
}

func (c *Client) setupTUN() error {
	// Проверяем наличие TAP драйвера
	if err := checkTAPDriver(); err != nil {
		log.Printf("TAP driver check failed: %v", err)
		log.Printf("Please install TAP Windows Adapter V9")
		log.Printf("You can do this by installing OpenVPN from https://openvpn.net/community-downloads/")
		return err
	}

	// Получаем имя TAP адаптера
	name, err := findTAPAdapter()
	if err != nil {
		return fmt.Errorf("failed to find TAP adapter: %v", err)
	}

	log.Printf("Using TAP adapter: %s", name)

	// Создаем конфигурацию для TAP
	cfg := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID:   "tap0901",
			InterfaceName: name,
			Network:       "0.0.0.0/0",
		},
	}

	// Создаем TAP интерфейс
	iface, err := water.New(cfg)
	if err != nil {
		// Если не получилось создать с найденным именем, пробуем стандартное
		if name != "Подключение по локальной сети" {
			log.Printf("Retrying with default interface name...")
			cfg.PlatformSpecificParams.InterfaceName = "Подключение по локальной сети"
			iface, err = water.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to create TAP interface: %v", err)
			}
			name = "Подключение по локальной сети"
		} else {
			return fmt.Errorf("failed to create TAP interface: %v", err)
		}
	}

	c.tunDevice = iface
	c.config.TunName = name

	// Даем системе время на инициализацию интерфейса
	time.Sleep(time.Second * 2)

	// Настраиваем интерфейс
	if err := c.configureTUN(); err != nil {
		c.tunDevice.Close()
		return fmt.Errorf("failed to configure TAP interface: %v", err)
	}

	log.Printf("TAP interface configured successfully")
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

func (c *Client) configureTUN() error {
	if c.assignedIP == nil {
		return fmt.Errorf("no IP address assigned")
	}

	log.Printf("Configuring TAP interface: %s", c.config.TunName)

	// Включаем интерфейс
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf(`
        $adapter = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue
        if ($adapter) {
            if ($adapter.Status -ne 'Up') {
                Enable-NetAdapter -Name '%s' -Confirm:$false
            }
        }
    `, c.config.TunName, c.config.TunName))

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to enable interface: %v, output: %s", err, output)
	}

	// Ждем активации интерфейса
	time.Sleep(time.Second * 2)

	// Удаляем существующие IP адреса
	cmd = exec.Command("powershell", "-Command", fmt.Sprintf(`
        Remove-NetIPAddress -InterfaceAlias '%s' -Confirm:$false -ErrorAction SilentlyContinue
    `, c.config.TunName))
	cmd.Run() // Игнорируем ошибки

	time.Sleep(time.Second)

	// Настраиваем IP адрес
	prefix, _ := c.subnetMask.Size()
	cmd = exec.Command("powershell", "-Command", fmt.Sprintf(`
        New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength %d
    `, c.config.TunName, c.assignedIP.String(), prefix))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP address: %v, output: %s", err, output)
	}

	// Устанавливаем MTU
	cmd = exec.Command("powershell", "-Command", fmt.Sprintf(`
        Set-NetIPInterface -InterfaceAlias '%s' -NlMtuBytes %d
    `, c.config.TunName, c.config.MTU))
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to set MTU: %v, output: %s", err, output)
	}

	// Отправляем тестовый пакет
	if err := c.sendTestPacket(); err != nil {
		log.Printf("Warning: test packet failed: %v", err)
	}

	return nil
}

func (c *Client) sendTestPacket() error {
	// Создаем тестовый ICMP эхо-запрос
	packet := make([]byte, 28)

	// IP заголовок
	packet[0] = 0x45                              // IPv4, IHL=5
	packet[1] = 0x00                              // DSCP=0, ECN=0
	binary.BigEndian.PutUint16(packet[2:4], 28)   // Total Length
	binary.BigEndian.PutUint16(packet[4:6], 1234) // ID
	packet[6] = 0x40                              // Don't Fragment
	packet[7] = 0x00                              // Fragment Offset
	packet[8] = 64                                // TTL
	packet[9] = 1                                 // Protocol (ICMP)

	// IP адреса
	copy(packet[12:16], c.assignedIP.To4()) // Source IP

	// Адрес сервера VPN (первый хост в сети)
	serverIP := make(net.IP, 4)
	copy(serverIP, c.assignedIP.Mask(c.subnetMask))
	serverIP[3] = 1 // Первый адрес для сервера
	copy(packet[16:20], serverIP)

	// Контрольная сумма IP заголовка
	binary.BigEndian.PutUint16(packet[10:12], 0)
	checksum := calculateIPChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	// ICMP заголовок
	packet[20] = 8                               // Type (Echo Request)
	packet[21] = 0                               // Code
	binary.BigEndian.PutUint16(packet[22:24], 0) // Checksum (пока 0)
	binary.BigEndian.PutUint16(packet[24:26], 1) // Identifier
	binary.BigEndian.PutUint16(packet[26:28], 1) // Sequence number

	// Контрольная сумма ICMP
	icmpChecksum := calculateICMPChecksum(packet[20:])
	binary.BigEndian.PutUint16(packet[22:24], icmpChecksum)

	log.Printf("Sending test packet: %x", packet)
	_, err := c.tunDevice.Write(packet)
	return err
}

func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	// Складываем переносы
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func calculateICMPChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i:]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func (c *Client) configureRoutes() error {
	log.Printf("Configuring routes...")

	// 1. Принудительно включаем TAP интерфейс
	cmd := exec.Command("netsh", "interface", "set", "interface", c.config.TunName, "admin=enabled")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to enable TAP interface: %v, output: %s", err, output)
	}
	time.Sleep(1 * time.Second)

	// 2. Получаем информацию о Wi-Fi и текущем шлюзе
	cmd = exec.Command("powershell", "-Command", `
		$wifi = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and ($_.InterfaceDescription -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*")} | Select-Object -First 1
		$config = Get-NetIPConfiguration -InterfaceIndex $wifi.InterfaceIndex
		$gateway = $config.IPv4DefaultGateway.NextHop
		$metric = $config.IPv4DefaultGateway.RouteMetric
		Write-Host "$gateway|$($wifi.InterfaceIndex)|$metric"
	`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get Wi-Fi info: %v", err)
	}
	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 3 {
		return fmt.Errorf("invalid Wi-Fi info format")
	}
	wifiGateway := parts[0]
	wifiMetric := parts[2]
	c.oldDefaultGateway = wifiGateway

	// 3. Получаем индекс TAP интерфейса
	cmd = exec.Command("powershell", "-Command", `
		$tap = Get-NetAdapter | Where-Object { $_.Name -eq '`+c.config.TunName+`' }
		Write-Host $tap.InterfaceIndex
	`)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get TAP interface index: %v", err)
	}
	tapIndex := strings.TrimSpace(string(output))

	// 4. Очищаем существующие маршруты через PowerShell для большей надежности
	cmd = exec.Command("powershell", "-Command", `
		Remove-NetRoute -InterfaceIndex `+tapIndex+` -Confirm:$false -ErrorAction SilentlyContinue
	`)
	cmd.Run()
	time.Sleep(500 * time.Millisecond)

	// 5. Настраиваем маршруты с правильными метриками
	serverHost := strings.Split(c.config.ServerAddr, ":")[0]
	vpnMetric := "1" // VPN маршруты должны иметь более низкую метрику

	routes := []struct {
		args []string
		desc string
	}{
		{
			args: []string{"add", serverHost, "mask", "255.255.255.255", wifiGateway, "metric", wifiMetric},
			desc: "server route",
		},
		{
			args: []string{"add", "10.0.0.0", "mask", "255.255.255.0", "10.0.0.1", "metric", vpnMetric, "if", tapIndex},
			desc: "VPN network route",
		},
		{
			args: []string{"add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", vpnMetric, "if", tapIndex},
			desc: "default route",
		},
	}

	for _, route := range routes {
		cmd = exec.Command("route", route.args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Failed to add %s: %v, output: %s", route.desc, err, output)
			// Пробуем альтернативный вариант без метрики
			altArgs := route.args[:len(route.args)-2] // Убираем метрику и индекс интерфейса
			cmd = exec.Command("route", altArgs...)
			if output, err = cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to add %s: %v", route.desc, err)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 6. Настраиваем DNS через PowerShell для большей надежности
	cmd = exec.Command("powershell", "-Command", `
        Set-DnsClientServerAddress -InterfaceIndex `+tapIndex+` -ResetServerAddresses
    `)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to reset DNS servers: %v, output: %s", err, output)
	}

	// 7. Сбрасываем DNS-кэш
	exec.Command("ipconfig", "/flushdns").Run()

	// 8. Проверяем состояние маршрутизации
	if !c.verifyRoutes() {
		return fmt.Errorf("route verification failed")
	}

	return nil
}

func (c *Client) verifyRoutes() bool {
	// Получаем полную таблицу маршрутизации
	cmd := exec.Command("route", "print")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to get routing table: %v", err)
		return false
	}
	
	routeTable := string(output)
	log.Printf("Current routing table:\n%s", routeTable)

	// Проверяем состояние TAP интерфейса через PowerShell
	cmd = exec.Command("powershell", "-Command", `
		$adapter = Get-NetAdapter | Where-Object { $_.Name -eq '`+c.config.TunName+`' }
		if ($adapter.Status -eq 'Up') { 
			Write-Host "UP"
		} else {
			Write-Host "DOWN"
		}
	`)
	
	output, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "UP") {
		log.Printf("TAP interface is not up: %v, status: %s", err, string(output))
		return false
	}

	// Проверяем наличие критических маршрутов
	requiredRoutes := []struct {
		network string
		gateway string
		desc    string
	}{
		{"0.0.0.0", "10.0.0.1", "default route"},
		{"10.0.0.0", "10.0.0.1", "VPN network"},
		{strings.Split(c.config.ServerAddr, ":")[0], c.oldDefaultGateway, "VPN server"},
	}

	success := true
	for _, route := range requiredRoutes {
		found := false
		lines := strings.Split(routeTable, "\n")
		for _, line := range lines {
			if strings.Contains(line, route.network) && strings.Contains(line, route.gateway) {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Missing required %s: network=%s, gateway=%s", 
				route.desc, route.network, route.gateway)
			success = false
		}
	}

	if !success {
		log.Printf("Route verification failed. Please check the routing table above for details.")
	} else {
		log.Printf("Route verification successful")
	}

	return success
}

func getDefaultRouteWindows() (*Route, error) {
	cmd := exec.Command("powershell", "-Command", `
        $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | 
        Where-Object { $_.NextHop -ne "::" -and $_.NextHop -ne "0.0.0.0" } |
        Select-Object -First 1;
        $interface = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex;
        Write-Host "$($defaultRoute.NextHop),$($interface.Name)"
    `)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get routing table: %v", err)
	}

	parts := strings.Split(strings.TrimSpace(string(output)), ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected output format")
	}

	gateway := net.ParseIP(parts[0])
	if gateway == nil {
		return nil, fmt.Errorf("invalid gateway IP")
	}

	return &Route{
		Gateway:   gateway,
		Interface: parts[1],
	}, nil
}

func (c *Client) cleanup() error {
	log.Printf("Cleaning up...")

	// Восстанавливаем оригинальные DNS настройки
	cmd := exec.Command("powershell", "-Command", `
		if (Test-Path "$env:TEMP\original_dns.txt") {
			$dns = Get-Content "$env:TEMP\original_dns.txt"
			$adapter = Get-NetAdapter | Where-Object {$_.Name -eq '`+c.config.TunName+`'}
			Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dns
			Remove-Item "$env:TEMP\original_dns.txt"
		}
	`)
	cmd.Run()

	// 1. Удаляем маршрут по умолчанию через VPN
	cmd = exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0")
	cmd.Run()
	time.Sleep(time.Second)

	// 2. Восстанавливаем старый маршрут по умолчанию
	if c.oldDefaultGateway != "" {
		cmd = exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", c.oldDefaultGateway)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: failed to restore default route: %v, output: %s", err, output)
		}
	}

	// 3. Удаляем VPN маршруты
	cmd = exec.Command("route", "delete", "10.0.0.0", "mask", "255.255.255.0")
	cmd.Run()

	// 4. Восстанавливаем автоматические DNS настройки
	cmd = exec.Command("powershell", "-Command", `
        $wifi = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.InterfaceDescription -like "*Wi-Fi*"} | Select-Object -First 1
        Set-DnsClientServerAddress -InterfaceIndex $wifi.InterfaceIndex -ResetServerAddresses
    `)
	cmd.Run()

	// 5. Восстанавливаем автоматические метрики
	cmd = exec.Command("powershell", "-Command", `
        Set-NetIPInterface -AutomaticMetric Enabled -AddressFamily IPv4
    `)
	cmd.Run()

	log.Printf("Cleanup completed")
	return nil
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
	serverHost := strings.Split(c.config.ServerAddr, ":")[0]
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

func (c *Client) handleTunToUDP() {
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
			if len(packet) < 20 {
				log.Printf("Packet too short")
				continue
			}

			// Проверяем и исправляем версию IP
			version := packet[0] >> 4
			if version != 4 {
				packet[0] = 0x45
				log.Printf("Fixed IP version to IPv4")
			}

			// Получаем и проверяем IP адреса
			srcIP := net.IP(packet[12:16])
			dstIP := net.IP(packet[16:20])

			// Проверяем и исправляем IP источника
			_, vpnNet, _ := net.ParseCIDR("10.0.0.0/24")
			if !vpnNet.Contains(srcIP) {
				copy(packet[12:16], c.assignedIP.To4())
				log.Printf("Fixed source IP from %s to %s", srcIP, c.assignedIP)
			}

			// Проверяем IP назначения
			if dstIP == nil || dstIP.To4() == nil || dstIP.IsLoopback() || dstIP.IsMulticast() || dstIP[0] == 0 {
				log.Printf("Invalid destination IP: %s, dropping packet", dstIP)
				continue
			}

			// Пересчитываем контрольную сумму
			packet[10] = 0
			packet[11] = 0
			var sum uint32
			for i := 0; i < 20; i += 2 {
				sum += uint32(packet[i])<<8 | uint32(packet[i+1])
			}
			for sum>>16 != 0 {
				sum = (sum & 0xFFFF) + (sum >> 16)
			}
			checksum := ^uint16(sum)
			packet[10] = byte(checksum >> 8)
			packet[11] = byte(checksum)

			// Создаем nonce для шифрования
			nonce := make([]byte, chacha20poly1305.NonceSize)
			copy(nonce, c.clientNonce[:])
			binary.BigEndian.PutUint64(nonce[len(nonce)-8:], c.sequenceNum)

			// Шифруем пакет
			encrypted := c.aead.Seal(nil, nonce, packet, nil)

			// Создаем заголовок пакета
			header := &protocol.PacketHeader{
				Version:     protocol.ProtocolVersion,
				Type:        protocol.PacketTypeData,
				SequenceNum: c.sequenceNum,
				PayloadSize: uint32(len(encrypted)),
			}

			// Увеличиваем sequence number
			c.sequenceNum++

			// Формируем полный пакет
			fullPacket := append(header.Marshal(), encrypted...)

			log.Printf("Sending encrypted packet: src=%s dst=%s, size=%d", srcIP, dstIP, len(fullPacket))
			_, err = c.udpConn.WriteToUDP(fullPacket, c.serverAddr)
			if err != nil {
				log.Printf("Error sending packet to server: %v", err)
			}
		}
	}
}

func (c *Client) handleUDPToTun() {
	defer c.wg.Done()

	buffer := make([]byte, protocol.MaxPacketSize)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Читаем пакет из UDP
		n, addr, err := c.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}
		log.Printf("Received %d bytes from UDP %v", n, addr)

		// Проверяем, что пакет от нашего сервера
		if addr.String() != c.serverAddr.String() {
			log.Printf("Received packet from unknown sender: %v", addr)
			continue
		}

		// Разбираем заголовок
		header, err := protocol.UnmarshalHeader(buffer[:protocol.HeaderSize])
		if err != nil {
			log.Printf("Error parsing header: %v", err)
			continue
		}

		// Проверяем размер пакета
		if n < int(protocol.HeaderSize+header.PayloadSize) {
			log.Printf("Packet too small: expected %d, got %d", protocol.HeaderSize+header.PayloadSize, n)
			continue
		}

		switch header.Type {
		case protocol.PacketTypeData:
			// Создаем nonce для расшифровки
			nonce := make([]byte, chacha20poly1305.NonceSize)
			copy(nonce, c.serverNonce[:])
			binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

			// Расшифровываем данные
			decrypted, err := c.aead.Open(nil, nonce, buffer[protocol.HeaderSize:n], nil)
			if err != nil {
				log.Printf("Error decrypting data: %v", err)
				continue
			}

			log.Printf("Successfully decrypted %d bytes", len(decrypted))
			if len(decrypted) >= 20 {
				srcIP := net.IP(decrypted[12:16])
				dstIP := net.IP(decrypted[16:20])
				log.Printf("Decrypted packet: src=%s dst=%s", srcIP, dstIP)
			}

			// Пишем в TUN интерфейс
			if _, err := c.tunDevice.Write(decrypted); err != nil {
				log.Printf("Error writing to TUN: %v", err)
			}

		case protocol.PacketTypeKeepalive:
			// Просто логируем получение keepalive
			log.Printf("Received keepalive packet")

		case protocol.PacketTypeDisconnect:
			log.Printf("Received disconnect signal from server")
			c.cancel()
			return
		}
	}
}

func (c *Client) keepalive() {
	defer c.wg.Done()

	ticker := time.NewTicker(protocol.KeepaliveInterval * time.Second)
	routeCheckTicker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer routeCheckTicker.Stop()

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
				log.Printf("Error sending keepalive: %v", err)
			}
		case <-routeCheckTicker.C:
			if !c.verifyRoutes() {
				log.Printf("Routes verification failed, reconfiguring...")
				if err := c.configureRoutes(); err != nil {
					log.Printf("Failed to reconfigure routes: %v", err)
				}
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
			log.Printf("Read %d bytes from TUN", n)

			// Обрабатываем пакет перед анализом
			if err := c.handleTUNPacket(packet); err != nil {
				continue
			}

			// Анализируем пакет
			if len(packet) >= 20 {
				srcIP := net.IP(packet[12:16])
				dstIP := net.IP(packet[16:20])
				log.Printf("Packet from TUN: src=%s dst=%s", srcIP, dstIP)

				// Отправляем пакет на сервер
				if err := c.sendPacketToServer(packet); err != nil {
					log.Printf("Error sending packet to server: %v", err)
				}
			}
		}
	}
}

func (c *Client) sendPacketToServer(packet []byte) error {
	// Создаем nonce для шифрования
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, c.clientNonce[:])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], c.sequenceNum)

	// Шифруем пакет
	encrypted := c.aead.Seal(nil, nonce, packet, nil)

	// Создаем заголовок пакета
	header := &protocol.PacketHeader{
		Version:     protocol.ProtocolVersion,
		Type:        protocol.PacketTypeData,
		SequenceNum: c.sequenceNum,
		PayloadSize: uint32(len(encrypted)),
	}
	c.sequenceNum++

	// Формируем полный пакет
	fullPacket := append(header.Marshal(), encrypted...)

	// Отправляем на сервер
	_, err := c.udpConn.WriteToUDP(fullPacket, c.serverAddr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	return nil
}

func (c *Client) handleTUNPacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Проверяем и исправляем версию IP
	version := packet[0] >> 4
	if version != 4 {
		// Устанавливаем версию IPv4 (0x45 = IPv4 + стандартный заголовок)
		packet[0] = 0x45
		log.Printf("Fixed IP version to IPv4")
	}

	// Получаем адреса источника и назначения
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Проверяем и исправляем IP источника если он не из нашей подсети
	if !c.isInVPNSubnet(srcIP) {
		copy(packet[12:16], c.ip.To4())
		log.Printf("Fixed source IP from %s to %s", srcIP, c.ip)
	}

	// Проверяем IP назначения
	if !c.isValidDestination(dstIP) {
		log.Printf("Invalid destination IP: %s, dropping packet", dstIP)
		return fmt.Errorf("invalid destination IP")
	}

	// Пересчитываем контрольную сумму IP-заголовка
	c.recalculateIPChecksum(packet)

	return nil
}

func (c *Client) isInVPNSubnet(ip net.IP) bool {
	_, vpnNet, _ := net.ParseCIDR("10.0.0.0/24")
	return vpnNet.Contains(ip)
}

func (c *Client) isValidDestination(ip net.IP) bool {
	// Проверяем что это валидный IPv4 адрес
	if ip == nil || ip.To4() == nil {
		return false
	}

	// Проверяем что это не специальные адреса
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}

	// Проверяем что первый октет не 0
	return ip[0] != 0
}

func (c *Client) recalculateIPChecksum(packet []byte) {
	// Сбрасываем текущую контрольную сумму
	packet[10] = 0
	packet[11] = 0

	// Считаем новую контрольную сумму
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	// Добавляем переносы
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Записываем новую контрольную сумму
	checksum := ^uint16(sum)
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)
}

func (c *Client) testTunnel() error {
	log.Printf("Testing VPN tunnel...")

	// 1. Пробуем пинг до шлюза VPN
	cmd := exec.Command("ping", "-n", "1", "-w", "3000", "10.0.0.1")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("VPN gateway ping failed: %v, output: %s", err, output)
		
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
