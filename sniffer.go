package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/xtaci/kcp-go"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

type UniCmdItem struct {
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var getPlayerTokenRspPacketId uint16

// var getPlayerTokenReqPacketId uint16
var unionCmdNotifyPacketId uint16

var initialKey = make(map[uint16][]byte)
var sessionSeed uint64
var serverSeed uint64
var sentMs uint64

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File

var packetCounter uint32
var foundAchievementAllDataNotify bool
var possibleServerSeeds = make(map[int32]uint64)
var deducedPacketIds = make(map[uint16]string)

func openPcap(fileName string) {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)
	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

func readKeys() {
	var initialKeyJson map[uint16]string
	file, err := os.ReadFile("./data/Keys.json")
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Keys.json #1", err)
	}
	err = json.Unmarshal(file, &initialKeyJson)
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Keys.json #2", err)
	}

	for k, v := range initialKeyJson {
		decode, _ := base64.RawStdEncoding.DecodeString(v)
		initialKey[k] = decode
	}

	// getPlayerTokenReqPacketId = packetNameMap["GetPlayerTokenReq"]
	getPlayerTokenRspPacketId = packetNameMap["GetPlayerTokenRsp"]
	unionCmdNotifyPacketId = packetNameMap["UnionCmdNotify"]
}

func startSniffer() {
	defer captureHandler.Close()

	err := captureHandler.SetBPFFilter("udp portrange 22101-22102")
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	kcpMap = make(map[string]*kcp.KCP)

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	packetCounter = 0
	foundAchievementAllDataNotify = false

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		capTime := packet.Metadata().Timestamp
		data := packet.ApplicationLayer().Payload()
		udp := packet.TransportLayer().(*layers.UDP)
		fromServer := udp.SrcPort == 22101 || udp.SrcPort == 22102

		if len(data) <= 20 {
			handleSpecialPacket(data, fromServer, capTime)
			packetCounter = 0
			foundAchievementAllDataNotify = false
			continue
		}

		handleKcp(data, fromServer, capTime)
	}
}

func handleKcp(data []byte, fromServer bool, capTime time.Time) {
	data = reformData(data)
	conv := binary.LittleEndian.Uint32(data[:4])
	key := strconv.Itoa(int(conv))
	if fromServer {
		key += "svr"
	} else {
		key += "cli"
	}

	if _, ok := kcpMap[key]; !ok {
		kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
		kcpInstance.WndSize(1024, 1024)
		kcpMap[key] = kcpInstance
	}
	kcpInstance := kcpMap[key]
	_ = kcpInstance.Input(data, true, true)

	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		handleProtoPacket(kcpBytes, fromServer, capTime)
		size = kcpInstance.PeekSize()
	}
	kcpInstance.Update()
}

func handleSpecialPacket(data []byte, fromServer bool, timestamp time.Time) {
	sessionSeed = 0
	serverSeed = 0
	sentMs = 0
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xFF:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke pls.")
	case 404:
		buildPacketToSend(data, fromServer, timestamp, 0, "Disconnected.")
	default:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke estamblished.")
	}
}

func handleProtoPacket(data []byte, fromServer bool, timestamp time.Time) {
	key := binary.BigEndian.Uint16(data[:4])
	key = key ^ 0x4567
	// log.Println("Key:", key)
	var xorPad []byte
	// log.Println("Before Decryption:", data)
	xorPad = initialKey[key]
	if initialKey[key] == nil {
		seed := sessionSeed
		if seed == 0 {
			seed = sentMs
			log.Println("seed set to sentMs:", sentMs)
		}
		log.Println("Cracking seed...")
		if config.AutoFindMinimalProto {
			for tag, value := range possibleServerSeeds {
				possibleSeed, possibleXorPad := bruteforce(seed, value, data)
				if possibleXorPad != nil {
					serverSeed = value
					seed = possibleSeed
					xorPad = possibleXorPad
					writeProto("GetPlayerTokenRsp", map[int32]string{tag: "string server_rand_key"}, "", "")
					continue
				}
			}
		} else {
			seed, xorPad = bruteforce(seed, serverSeed, data)
		}
		if seed == 0 || xorPad == nil {
			closeHandle()
			log.Fatal("Could not find key to decrypt,", key)
		}
		log.Println("Cracked seed", seed)
		if sessionSeed == 0 {
			sessionSeed = seed
		}
		initialKey[key] = xorPad
	}

	xorDecrypt(data, xorPad)
	// log.Println("After Decryption:", data)
	firstBytes := binary.BigEndian.Uint16(data[:2])
	if firstBytes != 0x4567 {
		log.Fatal("Expected first two bytes to be 0x4567, but got 0x", strconv.FormatUint(uint64(firstBytes), 16))
	}

	packetId := binary.BigEndian.Uint16(data[2:4])
	// log.Println("packetID:", packetId, data[2:4])
	var objectJson interface{}

	// useless now
	//if packetId == getPlayerTokenReqPacketId {
	//	data, objectJson = handleGetPlayerTokenReqPacket(data, packetId, timestamp, objectJson)
	//} else
	if config.AutoFindMinimalProto {
		packetCounter++
		header, data2 := getHeaderAndBody(data)

		if packetCounter == 2 {
			log.Println("second packet, assuming GetPlayerTokenRsp")
			possibleSeeds, err := unkGetPlayerTokenRsp(data2)
			if err == nil {
				possibleServerSeeds = possibleSeeds
				// Indeed, sent_ms of Rsp is the same as the Req
				head := msgMap["PacketHead"]
				dMsgHead := dynamic.NewMessage(head)
				_ = dMsgHead.Unmarshal(header)
				sentMs = dMsgHead.GetFieldByName("sent_ms").(uint64)

				deducedPacketIds[packetId] = "GetPlayerTokenRsp"
				packetIdMap[packetId] = "GetPlayerTokenRsp"
				packetNameMap["GetPlayerTokenRsp"] = packetId
				LoadProto("GetPlayerTokenRsp")
			} else {
				log.Println("Didn't get GetPlayerTokenRsp, retrying for next packet...")
				packetCounter = 1
			}
		} else if packetCounter >= 3 && !foundAchievementAllDataNotify {
			err := unkAchievementAllDataNotify(data2)
			if err == nil {
				foundAchievementAllDataNotify = true
				deducedPacketIds[packetId] = "AchievementAllDataNotify"
				packetIdMap[packetId] = "AchievementAllDataNotify"
				packetNameMap["AchievementAllDataNotify"] = packetId
				LoadProto("AchievementAllDataNotify")
			}
		}

		if len(deducedPacketIds) == 2 {
			writePacketIds(deducedPacketIds)
		}

		data = removeHeaderForParse(data)
		objectJson = parseProtoToInterface(packetId, data)
	} else {
		if packetId == getPlayerTokenRspPacketId {
			data, objectJson = handleGetPlayerTokenRspPacket(data, packetId, objectJson)
		} else if packetId == unionCmdNotifyPacketId {
			data, objectJson = handleUnionCmdNotifyPacket(data, packetId, objectJson)
		} else {
			data = removeHeaderForParse(data)
			objectJson = parseProtoToInterface(packetId, data)
		}
	}
	buildPacketToSend(data, fromServer, timestamp, packetId, objectJson)
}

//func handleGetPlayerTokenReqPacket(data []byte, packetId uint16, timestamp time.Time, objectJson interface{}) ([]byte, interface{}) {
//	header, data2 := getHeaderAndBody(data)
//	data = data2
//	dMsg, err := parseProto(packetId, data)
//	if err != nil {
//		log.Println("Could not parse GetPlayerTokenReqPacket proto", err)
//		closeHandle()
//	}
//	oj, err := dMsg.MarshalJSON()
//	if err != nil {
//		log.Println("Could not parse GetPlayerTokenReqPacket proto", err)
//		closeHandle()
//	}
//	err = json.Unmarshal(oj, &objectJson)
//	if err != nil {
//		log.Println("Could not parse GetPlayerTokenReqPacket proto", err)
//		closeHandle()
//	}
//
//	// sentMs = uint64(timestamp.UnixMilli())
//	head := msgMap["PacketHead"]
//	dMsgHead := dynamic.NewMessage(head)
//	_ = dMsgHead.Unmarshal(header)
//	sentMs = dMsgHead.GetFieldByName("sent_ms").(uint64)
//
//	return data, objectJson
//}

func handleGetPlayerTokenRspPacket(data []byte, packetId uint16, objectJson interface{}) ([]byte, interface{}) {
	// data = removeMagic(data)
	header, data2 := getHeaderAndBody(data)
	data = data2
	log.Println(packetId)
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse GetPlayerTokenRspPacket proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse GetPlayerTokenRspPacket proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse GetPlayerTokenRspPacket proto", err)
		closeHandle()
	}
	serverRandKey := dMsg.GetFieldByName("server_rand_key").(string)
	seed, err := base64.StdEncoding.DecodeString(serverRandKey)
	if err != nil {
		log.Println("Failed to decode server rand key")
		closeHandle()
	}
	seed, err = decrypt("data/private_key_5.pem", seed)
	if err != nil {
		log.Println("Failed to decrypt server rand key")
		closeHandle()
	}
	serverSeed = binary.BigEndian.Uint64(seed)
	log.Println("Server seed", serverSeed)

	// Indeed, sent_ms of Rsp is the same as the Req
	head := msgMap["PacketHead"]
	dMsgHead := dynamic.NewMessage(head)
	_ = dMsgHead.Unmarshal(header)
	sentMs = dMsgHead.GetFieldByName("sent_ms").(uint64)

	return data, objectJson
}

func handleUnionCmdNotifyPacket(data []byte, packetId uint16, objectJson interface{}) ([]byte, interface{}) {
	data = removeHeaderForParse(data)
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse UnionCmdNotify proto", err)
	}

	cmdList := dMsg.GetFieldByName("cmd_list").([]interface{})
	cmdListJson := make([]*UniCmdItem, len(cmdList))
	for i, item := range cmdList {
		msgItem := item.(*dynamic.Message)
		itemPacketId := uint16(msgItem.GetFieldByName("message_id").(uint32))
		itemData := msgItem.GetFieldByName("body").([]byte)

		childJson := parseProtoToInterface(itemPacketId, itemData)

		cmdListJson[i] = &UniCmdItem{
			PacketId:   itemPacketId,
			PacketName: GetProtoNameById(itemPacketId),
			Object:     childJson,
			Raw:        itemData,
		}
	}
	return data, cmdListJson
}

func buildPacketToSend(data []byte, fromSever bool, timestamp time.Time, packetId uint16, objectJson interface{}) {
	packet := &Packet{
		Time:       timestamp.UnixMilli(),
		FromServer: fromSever,
		PacketId:   packetId,
		PacketName: GetProtoNameById(packetId),
		Object:     objectJson,
		Raw:        data,
	}

	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	// log.Println("json", string(jsonResult))
	logPacket(packet)

	if GetProtoNameById(packetId) != "" && packetFilter[GetProtoNameById(packetId)] {
		return
	}
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "Rsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "Req") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Notify") {
		forward = "i->"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)

	if packet.PacketId == unionCmdNotifyPacketId {
		logUnionCmdNotifyPacket(packet)
	}
}

func logUnionCmdNotifyPacket(packet *Packet) {
	uniCmdItem, ok := packet.Object.([]*UniCmdItem)
	if !ok {
		log.Println("Error: unable to convert objectJson to []*UniCmdItem")
		return
	}

	for i, item := range uniCmdItem {
		group := "├─"
		if i == len(uniCmdItem) {
			group = "└─"
		}

		log.Println("\t",
			"\t",
			color.CyanString(group),
			"\t",
			color.RedString(item.PacketName),
			color.YellowString("#"+strconv.Itoa(int(item.PacketId))),
			"\t",
			len(item.Raw),
		)
	}
}
