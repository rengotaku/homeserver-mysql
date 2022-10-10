// go build -a main.go
package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	models "homeserver-mysql/models"

	"github.com/joho/godotenv"
	"gorm.io/gorm"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	MaxBatchNum = 1000
)

type layersData struct {
	LayName    string                 `json:"layerName"`
	Attributes map[string]interface{} `json:"attributes"`
	ErrorFlg   bool                   `json:"errorFlag"`
	Timestamp  time.Time              `json:"timestamp"`
}

var (
	err        error
	handle     *pcap.Handle
	pcapFile   string
	db         *gorm.DB
	migrateFlg *bool
	rmfileFlg  *bool
	envPath    *string
	debugFlg   *bool
)

func init() {
	log.SetOutput(os.Stdout)

	migrateFlg = flag.Bool("migrate", false, "Initialize database. You need to create database before.")
	rmfileFlg = flag.Bool("rmfile", false, "Removal the specified pcap file.")
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
		fmt.Sprintf("rmfile: %t\n", *rmfileFlg),
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
		db.Migrator().DropTable(&models.Packet{})
		db.AutoMigrate(&models.Packet{})
		log.Debugln("Finish migration.")
	}
}

func dumpPacketInfo(packet gopacket.Packet) layersData {
	errFlg := false
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		errFlg = true
		log.Warningln("Error decoding some part of the packet:", err)
	}

	var layNames []string
	var layerData map[string]interface{}
	for _, layer := range packet.Layers() {
		layNames = append(layNames, layer.LayerType().String())
		res1B, _ := json.Marshal(layer)
		json.Unmarshal([]byte(string(res1B)), &layerData)
		delete(layerData, "Payload")
	}

	return layersData{
		LayName:    strings.Join(layNames[:], ","),
		Attributes: layerData,
		ErrorFlg:   errFlg,
		Timestamp:  packet.Metadata().Timestamp,
	}
}

func send_data(layersDatas []layersData) {
	err = db.Transaction(func(tx *gorm.DB) error {
		var packets []models.Packet
		for _, layersData := range layersDatas {
			attributes, _ := json.Marshal(layersData.Attributes)

			p := models.Packet{
				LayerName:  layersData.LayName,
				PacketJson: string(attributes),
				ErrorFlag:  layersData.ErrorFlg,
				CreatedAt:  layersData.Timestamp,
			}

			packets = append(packets, p)
		}
		if err := tx.Create(&packets).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	// Last argument
	argsWithoutProg := os.Args[len(os.Args)-1:]
	if len(argsWithoutProg) == 0 {
		fmt.Println("please use valid argument or use -h or --help for help menu")
		return
	}
	pcapFile = argsWithoutProg[0]
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer handle.Close()

	// // Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var layersDatas []layersData
	for packet := range packetSource.Packets() {
		layersData := dumpPacketInfo(packet)
		layersDatas = append(layersDatas, layersData)
	}
	log.Debugln("Packet length: ", len(layersDatas))

	cntChunk := (len(layersDatas) / MaxBatchNum)
	if (len(layersDatas) % MaxBatchNum) > 0 {
		cntChunk++
	}

	log.Debugln("Count of Chunk: ", cntChunk)

	for i := 0; i < cntChunk; i++ {
		if len(layersDatas) > MaxBatchNum*i+MaxBatchNum {
			send_data(layersDatas[MaxBatchNum*i : MaxBatchNum*(i+1)])
		} else {
			send_data(layersDatas[MaxBatchNum*i:])
		}
	}

	if *rmfileFlg {
		log.Debugln("Removal the pcap file.")
		e := os.Remove(pcapFile)
		if e != nil {
			log.Fatalln(e)
		}
	}
}
