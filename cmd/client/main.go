package main

import (
	"flag"
	"fmt"
	"github.com/neokofg/go-pet-vpn-client/internal/client"
	"github.com/neokofg/go-pet-vpn-client/internal/config"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	if err := checkElevatedPrivileges(); err != nil {
		log.Fatalf("Error: %v\nPlease run with sudo", err)
	}

	// Парсим аргументы командной строки
	serverAddr := flag.String("server", "localhost:8000", "VPN server address")
	token := flag.String("token", "", "Authentication token")
	tunName := flag.String("tun", "tun0", "TUN interface name")
	mtu := flag.Int("mtu", 1500, "MTU value")
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	// Проверяем наличие TUN/TAP драйвера
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
			log.Fatal("Error: TUN/TAP driver not available. Please install it:\n" +
				"For Ubuntu/Debian: sudo apt-get install linux-modules-extra-$(uname -r)\n" +
				"For CentOS/RHEL: sudo yum install kernel-devel\n" +
				"After installation, run: sudo modprobe tun")
		}
	}

	// Создаем конфигурацию
	cfg := &config.Config{
		ServerAddr: *serverAddr,
		Token:      *token,
		TunName:    *tunName,
		MTU:        *mtu,
	}

	// Создаем клиент
	vpnClient, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create VPN client: %v", err)
	}

	// Обработка сигналов для graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Канал для ошибок
	errChan := make(chan error, 1)

	// Запускаем клиент в отдельной горутине
	go func() {
		if err := vpnClient.Start(); err != nil {
			errChan <- fmt.Errorf("client error: %v", err)
		}
	}()

	// Ждем сигнала или ошибки
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
	case err := <-errChan:
		log.Printf("Error: %v", err)
	}

	// Graceful shutdown
	log.Println("Shutting down VPN client...")
	if err := vpnClient.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
}

func checkElevatedPrivileges() error {
	if runtime.GOOS == "windows" {
		return client.CheckAdminPrivileges()
	}
	return nil
}
