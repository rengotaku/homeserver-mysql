// go build -a main.go
package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	models "homeserver-mysql/models"

	"github.com/joho/godotenv"
	"gorm.io/gorm"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	_ "time/tzdata"
)

const (
	MaxBatchNum = 1000
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type IdentifiedPacket struct {
	DestIP     net.IP
	DestPort   layers.TCPPort
	HttpHeader http.Header
	HttpURL    *url.URL
}

type layersData struct {
	LayName          string                 `json:"layerName"`
	Attributes       map[string]interface{} `json:"attributes"`
	IdentifiedPacket IdentifiedPacket
	ErrorFlg         bool      `json:"errorFlag"`
	CaptureLength    int       `json:"captureLength"`
	Timestamp        time.Time `json:"timestamp"`
}

var (
	err        error
	handle     *pcap.Handle
	wg         sync.WaitGroup
	db         *gorm.DB
	_, _       = time.LoadLocation("Asia/Tokyo")
	device     *string
	migrateFlg *bool
	envPath    *string
	debugFlg   *bool
	selfIPs    []net.IP
)

func init() {
	os.Setenv("TZ", "Asia/Tokyo")
	log.SetOutput(os.Stdout)

	device = flag.String("dev", "eth0", "Sniffing capture device.")
	migrateFlg = flag.Bool("migrate", false, "Initialize database. You need to create database before.")
	envPath = flag.String("env", ".env", "Path of env file which is written database information, user, password and so on, or using environmental")
	if os.Getenv("ENV_FILE") != "" {
		*envPath = os.Getenv("ENV_FILE")
	}
	debugFlg = flag.Bool("v", false, "Verbose output somethings.")
	flag.Parse()

	if *debugFlg {
		log.SetLevel(log.DebugLevel)
	}
	log.Debugln(
		"Parameters:\n",
		fmt.Sprintf("migrate: %t\n", *migrateFlg),
		fmt.Sprintf("env: %s\n", *envPath),
	)

	err := godotenv.Load(*envPath)
	if err != nil {
		log.Fatalln("Error loading env file.")
	}

	config := models.DbConfig{
		DbHost:     os.Getenv("BD_HOST"),
		DbName:     os.Getenv("DB_NAME"),
		DbUser:     os.Getenv("DB_USER"),
		DbPassword: os.Getenv("DB_PASSWORD"),
	}
	if *debugFlg {
		j, _ := json.Marshal(config)
		log.Debugln(fmt.Sprintf("DbConfig: %s", string(j)))
	}

	db = models.Connection(config)

	if *migrateFlg {
		log.Debugln("Start migration.")
		db.Migrator().DropTable(&models.Packet{}, &models.RawPacket{})
		db.AutoMigrate(&models.RawPacket{})
		db.AutoMigrate(&models.Packet{})
		log.Debugln("Finish migration.")
	}
}

// func dumpPacketInfo(packet gopacket.Packet) layersData {
// 	errFlg := false
// 	// Check for errors
// 	if err := packet.ErrorLayer(); err != nil {
// 		errFlg = true
// 		log.Warningln("Error decoding some part of the packet:", err)
// 	}

// 	var layNames []string
// 	var layerData map[string]interface{}
// 	for _, layer := range packet.Layers() {
// 		layNames = append(layNames, layer.LayerType().String())
// 		res1B, _ := json.Marshal(layer)
// 		json.Unmarshal([]byte(string(res1B)), &layerData)
// 		delete(layerData, "Payload")
// 	}

// 	return layersData{
// 		LayName:       strings.Join(layNames[:], ","),
// 		Attributes:    layerData,
// 		ErrorFlg:      errFlg,
// 		CaptureLength: packet.Metadata().CaptureLength,
// 		Timestamp:     packet.Metadata().Timestamp,
// 	}
// }

func dumpPacketInfo(packet gopacket.Packet) *layersData {
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Warningln("Error decoding some part of the packet:", err)
		return nil
	}

	var layNames []string
	var layerData map[string]interface{}
	var idPacket IdentifiedPacket

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if ethernetPacket.EthernetType != layers.EthernetTypeIPv4 && ethernetPacket.EthernetType != layers.EthernetTypeIPv6 {
			return nil
		}
	}

	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)

		expectable := false
		for _, v := range selfIPs {
			if ip.SrcIP.Equal(v) {
				expectable = true
			}
		}
		if !expectable {
			return nil
		}

		idPacket.DestIP = ip.DstIP
		log.Debugln(fmt.Sprintf("From %s to %s\n", ip.SrcIP, ip.DstIP))
	}
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)

		expectable := false
		for _, v := range selfIPs {
			if ip.SrcIP.Equal(v) {
				expectable = true
			}
		}
		if !expectable {
			return nil
		}

		idPacket.DestIP = ip.DstIP
		log.Debugln(fmt.Sprintf("From %s to %s\n", ip.SrcIP, ip.DstIP))
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		idPacket.DestPort = tcp.DstPort
		log.Debugln(fmt.Sprintf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort))
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// fmt.Printf("%s\n", applicationLayer.Payload())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			payloadReader := bytes.NewReader(applicationLayer.Payload())
			bufferedPayloadReader := bufio.NewReader(payloadReader)

			request, _ := http.ReadRequest(bufferedPayloadReader)
			if request != nil {
				idPacket.HttpHeader = request.Header
				idPacket.HttpURL = request.URL
			}
		}
	}

	return &layersData{
		LayName:          strings.Join(layNames[:], ","),
		Attributes:       layerData,
		ErrorFlg:         false,
		IdentifiedPacket: idPacket,
		CaptureLength:    packet.Metadata().CaptureLength,
		Timestamp:        packet.Metadata().Timestamp,
	}
}

func send_data(lDatas []layersData) {
	err = db.Transaction(func(tx *gorm.DB) error {
		var rawPacks []models.RawPacket
		var packs []models.Packet
		for _, lData := range lDatas {
			attributes, _ := json.Marshal(lData.Attributes)

			rp := models.RawPacket{
				PacketJson: string(attributes),
			}
			rawPacks = append(rawPacks, rp)

			p := models.Packet{
				RawPacket: rp,
				LayerName: lData.LayName,
				ErrorFlag: lData.ErrorFlg,
				CreatedAt: lData.Timestamp,
			}

			if lData.Attributes["DstIP"] != nil {
				v := lData.Attributes["DstIP"].(string)
				p.DstIP = &v
			}
			if lData.Attributes["SrcIP"] != nil {
				v := lData.Attributes["SrcIP"].(string)
				p.SrcIP = &v
			}
			if lData.Attributes["DstMAC"] != nil {
				v := lData.Attributes["DstMAC"].(string)
				p.DstMAC = &v
			}
			if lData.Attributes["SrcMAC"] != nil {
				v := lData.Attributes["SrcMAC"].(string)
				p.SrcMAC = &v
			}
			if lData.Attributes["DstPort"] != nil {
				v := int(lData.Attributes["DstPort"].(float64))
				p.DstPort = &v
			}
			if lData.Attributes["SrcPort"] != nil {
				v := int(lData.Attributes["SrcPort"].(float64))
				p.SrcPort = &v
			}
			if lData.Attributes["Length"] != nil {
				v := int(lData.Attributes["Length"].(float64))
				p.Length = &v
			}
			if lData.Attributes["TTL"] != nil {
				v := int(lData.Attributes["TTL"].(float64))
				p.TTL = &v
			}

			packs = append(packs, p)
		}
		if err := tx.Create(&rawPacks).Error; err != nil {
			return err
		}
		if err := tx.Create(&packs).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Fatalln(err)
	}
	wg.Done()
}

func main() {
	// Find all devices
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln(err)
	}

	for _, dev := range devs {
		if *device == dev.Name {
			for _, address := range dev.Addresses {
				selfIPs = append(selfIPs, address.IP)
			}
		}
	}
	if len(selfIPs) <= 0 {
		log.Fatalln("The device dosen't exist: ", *device)
	}

	handle, err = pcap.OpenLive(*device, defaultSnapLen, false,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// if err := handle.SetBPFFilter("port 3030"); err != nil {
	// 	panic(err)
	// }

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Info("Start time: ", time.Now())
	log.Info("Device: ", *device)
	log.Info("IP address: ", selfIPs)

	var lDatas []layersData
	for packet := range packetSource.Packets() {
		lData := dumpPacketInfo(packet)
		if lData == nil {
			continue
		}
		lDatas = append(lDatas, *lData)

		// Bulk insert when over limit
		if len(lDatas) >= MaxBatchNum {
			log.Debugln("Packet length: ", len(lDatas))

			dupLDatas := lDatas
			wg.Add(1)
			go send_data(dupLDatas)
			lDatas = []layersData{}
		}
	}
	wg.Wait()

	send_data(lDatas)
}
