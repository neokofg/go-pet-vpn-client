package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	// Типы пакетов
	PacketTypeHandshake  = 1
	PacketTypeData       = 2
	PacketTypeKeepalive  = 3
	PacketTypeDisconnect = 4

	// Константы протокола
	MaxPacketSize   = 1400
	HeaderSize      = 16 // 4 байта версия + тип, 8 байт sequence number, 4 байта размер данных
	MaxPayloadSize  = MaxPacketSize - HeaderSize
	ProtocolVersion = 1

	// Параметры соединения
	KeepaliveInterval = 30 // seconds
	HandshakeTimeout  = 10 // seconds
)

// Заголовок пакета
type PacketHeader struct {
	Version     uint8
	Type        uint8
	Reserved    uint16 // Для будущего использования
	SequenceNum uint64 // Для детектирования повторов и порядка пакетов
	PayloadSize uint32
}

// Сериализация заголовка
func (h *PacketHeader) Marshal() []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = h.Version
	buf[1] = h.Type
	binary.BigEndian.PutUint16(buf[2:4], h.Reserved)
	binary.BigEndian.PutUint64(buf[4:12], h.SequenceNum)
	binary.BigEndian.PutUint32(buf[12:16], h.PayloadSize)
	return buf
}

// Десериализация заголовка
func UnmarshalHeader(data []byte) (*PacketHeader, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("packet too small")
	}

	header := &PacketHeader{
		Version:     data[0],
		Type:        data[1],
		Reserved:    binary.BigEndian.Uint16(data[2:4]),
		SequenceNum: binary.BigEndian.Uint64(data[4:12]),
		PayloadSize: binary.BigEndian.Uint32(data[12:16]),
	}

	if header.Version != ProtocolVersion {
		return nil, errors.New("unsupported protocol version")
	}

	return header, nil
}

// Структура для хендшейка
type HandshakePacket struct {
	Token        [64]byte // Токен авторизации
	ClientNonce  [24]byte // Нонс для ChaCha20
	ClientPubKey [32]byte // Публичный ключ для обмена ключами
}

func (h *HandshakePacket) Marshal() []byte {
	buf := make([]byte, 120) // 64 + 24 + 32
	copy(buf[0:64], h.Token[:])
	copy(buf[64:88], h.ClientNonce[:])
	copy(buf[88:120], h.ClientPubKey[:])
	return buf
}

func UnmarshalHandshake(data []byte) (*HandshakePacket, error) {
	if len(data) < 120 {
		return nil, errors.New("handshake packet too small")
	}

	hs := &HandshakePacket{}
	copy(hs.Token[:], data[0:64])
	copy(hs.ClientNonce[:], data[64:88])
	copy(hs.ClientPubKey[:], data[88:120])
	return hs, nil
}

type HandshakeResponse struct {
	ServerNonce [24]byte // Нонс сервера
	Key         [32]byte // Ключ шифрования
	AssignedIP  [4]byte  // Назначенный IP-адрес
	SubnetMask  [4]byte  // Маска подсети
	MTU         uint16   // MTU для туннеля
}

func (hr *HandshakeResponse) Marshal() []byte {
	buf := make([]byte, 66) // 24 + 32 + 4 + 4 + 2
	copy(buf[0:24], hr.ServerNonce[:])
	copy(buf[24:56], hr.Key[:])
	copy(buf[56:60], hr.AssignedIP[:])
	copy(buf[60:64], hr.SubnetMask[:])
	binary.BigEndian.PutUint16(buf[64:66], hr.MTU)
	return buf
}

func UnmarshalHandshakeResponse(data []byte) (*HandshakeResponse, error) {
	if len(data) < 66 {
		return nil, errors.New("handshake response packet too small")
	}

	hr := &HandshakeResponse{}
	copy(hr.ServerNonce[:], data[0:24])
	copy(hr.Key[:], data[24:56])
	copy(hr.AssignedIP[:], data[56:60])
	copy(hr.SubnetMask[:], data[60:64])
	hr.MTU = binary.BigEndian.Uint16(data[64:66])
	return hr, nil
}
