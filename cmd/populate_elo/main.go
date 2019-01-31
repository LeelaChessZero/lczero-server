package main

import (
	"db"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	//	"github.com/marcsauter/single"
)

func populateElo() {
	//  Get all networks.
	var networks []db.Network
	err := db.GetDB().Order("id").Find(&networks).Error
	if err != nil {
		log.Println("get network failed.")
		return
	}
	networkNums := make(map[uint]uint)
	for i, network := range networks {
		networkNums[network.NetworkNumber] = uint(i)
	}
	data, err := ioutil.ReadFile("match_pgns/output.csv")
	if err != nil {
		log.Println("Failed to read data.")
		return
	}
	fileContent := string(data)
	lines := strings.Split(fileContent, "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			continue
		}
		name := strings.Trim(parts[1], "\"")
		if !strings.HasPrefix(name, "lc0.net.") {
			continue
		}
		name = strings.TrimPrefix(name, "lc0.net.")
		netNum, err := strconv.ParseUint(name, 10, 32)
		elo, err := strconv.ParseFloat(parts[2], 64)
		idx := networkNums[uint(netNum)]
		network := networks[idx]
		if network.Anchor {
			continue
		}
		err = db.GetDB().Model(&network).Update("elo", elo).Error
		if err != nil {
			log.Println("Failed to update elo")
			return
		}
		err = db.GetDB().Model(&network).Update("elo_set", true).Error
		if err != nil {
			log.Println("Failed to update elo set status.")
			return
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	//	s := single.New("populate_elo")
	//	if err := s.CheckLock(); err != nil && err == single.ErrAlreadyRunning {
	//		log.Fatal("another instance of the app is already running, exiting")
	//	} else if err != nil {
	// Another error occurred, might be worth handling it as well
	//		log.Fatalf("failed to acquire exclusive app lock: %v", err)
	//	}
	//	defer s.TryUnlock()

	db.Init()
	defer db.Close()

	populateElo()
}
