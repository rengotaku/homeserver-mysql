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
	"time"

	log "github.com/sirupsen/logrus"

	models "homeserver-mysql/models"

	"github.com/joho/godotenv"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
	DestPort   uint16
	HttpHeader http.Header
	HttpURL    *url.URL
}

func (ld *layersData) ID() string {
	return fmt.Sprintf("%s:%d", ld.IdentifiedPacket.DestIP.String(), ld.IdentifiedPacket.DestPort)
}

func (ld *layersData) analyzePacket(packet gopacket.Packet) bool {
	var layNames []string
	var layerData map[string]interface{}
	var idPacket IdentifiedPacket

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
			return false
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
			return false
		}

		idPacket.DestIP = ip.DstIP
		log.Debug(fmt.Sprintf("From %s to %s\n", ip.SrcIP, ip.DstIP))
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		idPacket.DestPort = uint16(tcp.DstPort)
		log.Debug(fmt.Sprintf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort))
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)

		idPacket.DestPort = uint16(udp.DstPort)
		log.Debug(fmt.Sprintf("From port %d to %d\n", udp.SrcPort, udp.DstPort))
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

	log.Debugln()

	for _, layer := range packet.Layers() {
		layNames = append(layNames, layer.LayerType().String())
	}

	ld.LayName = strings.Join(layNames[:], ",")
	ld.CaptureLength = packet.Metadata().CaptureLength
	ld.Timestamp = packet.Metadata().Timestamp
	ld.Attributes = layerData
	ld.ErrorFlg = false
	ld.IdentifiedPacket = idPacket

	return true
}

type layersData struct {
	LayName          string                 `json:"layerName"`
	Attributes       map[string]interface{} `json:"attributes"`
	IdentifiedPacket IdentifiedPacket
	ErrorFlg         bool      `json:"errorFlag"`
	CaptureLength    int       `json:"captureLength"`
	EmergedTime      int       `json:"emergedTime"`
	Timestamp        time.Time `json:"timestamp"`
}

var (
	err         error
	pcapHandler *pcap.Handle
	db          *gorm.DB
	_, _        = time.LoadLocation("Asia/Tokyo")
	device      *string
	interval    *int
	migrateFlg  *bool
	envPath     *string
	debugFlg    *bool
	selfIPs     []net.IP
	timeout     *int
)

func init() {
	os.Setenv("TZ", "Asia/Tokyo")
	log.SetOutput(os.Stdout)

	device = flag.String("dev", "eth0", "Sniffing capture device.")
	migrateFlg = flag.Bool("migrate", false, "Initialize database. You need to create database before.")
	interval = flag.Int("interval", 60, "Interval of aggregating similar packets.")
	envPath = flag.String("env", ".env", "Path of env file which is written database information, user, password and so on, or using environmental")
	timeout = flag.Int("timeout", 30, "Hogehoge")
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
		fmt.Sprintf("interval: %d\n", *interval),
		fmt.Sprintf("timeout: %d\n", *timeout),
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

	db = models.Connection(config, *debugFlg)

	if *migrateFlg {
		log.Debugln("Start migration.")
		db.Migrator().DropTable(
			&models.RawPacket{},
			&models.Hostname{},
		)
		db.AutoMigrate(&models.Packet{})
		db.AutoMigrate(&models.Hostname{})
		log.Debugln("Finish migration.")
	}
}

func availablePacket(packet gopacket.Packet) bool {
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Warningln("Error decoding some part of the packet:", err)
		return false
	}

	// IPv4 or IPv6
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if ethernetPacket.EthernetType != layers.EthernetTypeIPv4 && ethernetPacket.EthernetType != layers.EthernetTypeIPv6 {
			return false
		}
	}

	return true
}

func sendData(rawLDatas []layersData) {
	keys := make(map[string]*layersData)
	for i, _ := range rawLDatas {
		ld := rawLDatas[i]
		key := ld.ID()
		if keys[key] != nil {
			keys[key].EmergedTime += 1
			keys[key].CaptureLength += ld.CaptureLength
		} else {
			ld.EmergedTime += 1
			keys[key] = &ld
		}
	}

	var lDatas []layersData
	for _, v := range keys {
		lDatas = append(lDatas, *v)
	}
	log.Infoln("Compressed data ", len(keys), " from ", len(rawLDatas))

	var ips []models.Hostname
	var packs []models.Packet
	for _, lData := range lDatas {
		p := models.Packet{
			LayerName:   lData.LayName,
			DstIP:       lData.IdentifiedPacket.DestIP.String(),
			DstPort:     int(lData.IdentifiedPacket.DestPort),
			EmergedTime: lData.EmergedTime,
			Length:      lData.CaptureLength,
			CreatedAt:   lData.Timestamp,
		}

		packs = append(packs, p)
		ips = append(ips, models.Hostname{IP: p.DstIP})
	}
	db.Create(&packs)
	db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&ips)
}

func detectIPs() []net.IP {
	// Find all devices
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln(err)
	}

	ips := []net.IP{}
	for _, dev := range devs {
		if *device == dev.Name {
			for _, address := range dev.Addresses {
				ips = append(ips, address.IP)
			}
		}
	}

	return ips
}

func sniffPackets(lDatas []layersData, lstTime *time.Time) {
	pcapHandler, err = pcap.OpenLive(*device, defaultSnapLen, false, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}

	packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())

	log.Info("Start time: ", time.Now())
	log.Info("Device: ", *device)
	log.Info("IP address: ", selfIPs)

	flushTim := time.NewTicker(time.Duration(*interval) * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			*lstTime = time.Now()

			// Maybe closing handle
			if packet == nil {
				return
			}

			if !availablePacket(packet) {
				continue
			}
			ld := layersData{}
			if !ld.analyzePacket(packet) {
				continue
			}

			lDatas = append(lDatas, ld)
		case <-flushTim.C: // Over interval
			log.Debugln("Packet length: ", len(lDatas))

			dupLDatas := lDatas
			if len(dupLDatas) > 0 {
				go sendData(dupLDatas)
			}
			lDatas = []layersData{}
		}
	}
}

func main() {
	var lDatas []layersData
	lstTime := time.Now()

	ips := detectIPs()
	if len(ips) == 0 {
		log.Fatalln("The device dosen't exist: ", *device)
	}
	selfIPs = ips

	go sniffPackets(lDatas, &lstTime)

	lupInv := 60
	if *debugFlg {
		lupInv = 10
	}
	lookupTim := time.NewTicker(time.Duration(lupInv) * time.Second)

	// Not sure interval is right.
	thoutTim := time.NewTicker(time.Duration(*timeout/3) * time.Second)
	// Checking whether connection is working.(In my case, connection as PPPoE is broken when it switch new IP address.)
	// If connection was broken, you'll stay to get a packet from packet channel.
	for {
		select {
		case now := <-thoutTim.C:
			log.Debugln("Time to check: ", now, lstTime)
			if now.Sub(lstTime) < time.Duration(*timeout)*time.Second {
				continue
			}

			if len(lDatas) > 0 {
				ds := lDatas
				lDatas = []layersData{}
				sendData(ds)
			}

			selfIPs = detectIPs()
			if len(selfIPs) == 0 {
				log.Warnln("Specific device dosen't exist: ", *device)

				thoutTim.Stop()
				// Waiting for reconnection until 180 seconds.
				for dRetrTim := 0; dRetrTim < 36; dRetrTim++ {
					time.Sleep(5 * time.Second)

					selfIPs = detectIPs()
					if len(selfIPs) > 0 {
						break
					}
				}
				if len(selfIPs) == 0 {
					log.Fatalln("Specific device dosen't exist: ", *device)
				}
				thoutTim.Reset(time.Duration(*timeout/3) * time.Second)
			}

			log.Warnln("Close packet stream")
			pcapHandler.Close()
			log.Warnln("Restarting sniffing packet stream")
			lstTime := time.Now()
			go sniffPackets(lDatas, &lstTime)
		case <-lookupTim.C:
			ips := []models.Hostname{}
			db.Where("hostname is null and error_flg = ?", false).Limit(10).Find(&ips)
			if len(ips) == 0 {
				continue
			}

			log.Infoln("Lookup ip addresses: ", len(ips))
			for _, ip := range ips {
				addr, err := net.LookupAddr(ip.IP)
				if err != nil {
					ip.ErrorFlg = true
				} else {
					ip.Hostname = &addr[0]
				}

				db.Save(&ip)
			}
		}
	}
}
