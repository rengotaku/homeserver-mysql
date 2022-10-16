package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"

	_ "time/tzdata"
)

type layersData struct {
	LayName    string                 `json:"layerName"`
	Attributes map[string]interface{} `json:"attributes"`
	ErrorFlg   bool                   `json:"errorFlag"`
	Timestamp  time.Time              `json:"timestamp"`
}

var (
	err      error
	handle   *pcap.Handle
	envPath  *string
	debugFlg *bool
	cstSh, _ = time.LoadLocation("Asia/Tokyo")
)

func init() {
	os.Setenv("TZ", "Asia/Tokyo")
	log.Info("Start time: ", time.Now())
	log.SetOutput(os.Stdout)

	validParams()

	err := godotenv.Load(*envPath)
	if err != nil {
		log.Fatalln("Error loading env file.")
	}
}

func validParams() {
	// Last argument
	argsWithoutProg := os.Args[len(os.Args)-1:]
	if len(argsWithoutProg) == 0 {
		fmt.Println("please use valid argument or use -h or --help for help menu")
		return
	}
	pcapFile := argsWithoutProg[0]
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalln(err)
		return
	}
	envPath = flag.String("env", ".env", "Path of env file which is written database information, user, password and so on, or using environmental 'ENV_FILE'")
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
		fmt.Sprintf("env: %s\n", *envPath),
	)
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

	if app := packet.ApplicationLayer(); app != nil {
		fmt.Println("Application layer/Payload found.")
		// fmt.Printf("%s\n", app.Payload())

		if strings.Contains(string(app.Payload()), "HTTP") {
			payloadReader := bytes.NewReader(app.Payload())
			bufferedPayloadReader := bufio.NewReader(payloadReader)

			request, _ := http.ReadRequest(bufferedPayloadReader)
			if request != nil {
				fmt.Println(request.Header)
				fmt.Println(request.URL)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				ip, _ := ipLayer.(*layers.IPv4)
				fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
			}
			// response, _ := http.ReadResponse(bufferedPayloadReader, request)
			// fmt.Println(response)
		}

	}

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

func main() {
	defer handle.Close()

	// // Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var lDatas []layersData
	for packet := range packetSource.Packets() {
		lData := dumpPacketInfo(packet)
		lDatas = append(lDatas, lData)

		// // Bulk insert when over limit
		// if len(lDatas) >= MaxBatchNum {
		// 	log.Debugln("Packet length: ", len(lDatas))

		// 	dupLDatas := lDatas
		// 	go send_data(dupLDatas)
		// 	lDatas = []layersData{}
		// }
	}

	f, err := os.Create("./test.json")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	// j, _ := json.Marshal(lDatas)
	j, _ := json.MarshalIndent(lDatas, "", "    ")
	_, err = f.Write(j)
	if err != nil {
		log.Fatalln(err)
	}

}
