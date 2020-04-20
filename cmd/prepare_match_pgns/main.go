package main

import (
	"db"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	//	"github.com/marcsauter/single"
)

func prepareMatches() {
	//  Get all matches and networks.
	var matches []db.Match
	err := db.GetDB().Order("id").Find(&matches).Error
	if err != nil {
		log.Println("get matches failed.")
		return
	}

	var networks []db.Network
	err = db.GetDB().Order("id").Find(&networks).Error
	if err != nil {
		log.Println("get network failed.")
		return
	}
	networkNums := make(map[uint]uint)
	anchors := make(map[uint][]uint)
	anchorMatches := make(map[uint][][]string)
	anchorsNew := make(map[uint][]bool)
	anchorElos := make(map[uint][]float64)
	for _, network := range networks {
		networkNums[network.ID] = network.NetworkNumber
		if network.Anchor {
			if anchors[network.TrainingRunID] == nil {
				anchors[network.TrainingRunID] = make([]uint, 0)
				anchorMatches[network.TrainingRunID] = make([][]string, 0)
				anchorsNew[network.TrainingRunID] = make([]bool, 0)
				anchorElos[network.TrainingRunID] = make([]float64, 0)
			}
			anchors[network.TrainingRunID] = append(anchors[network.TrainingRunID], network.NetworkNumber)
			anchorMatches[network.TrainingRunID] = append(anchorMatches[network.TrainingRunID], make([]string, 0))
			anchorsNew[network.TrainingRunID] = append(anchorsNew[network.TrainingRunID], false)
			anchorElos[network.TrainingRunID] = append(anchorElos[network.TrainingRunID], network.Elo)
		}
	}
	os.MkdirAll("match_pgns", os.ModePerm)
	log.Println("Starting matches")
	var ordoScript strings.Builder
	ordoScript.WriteString("#!/bin/bash\n\n")
	ordoScript.WriteString("rm match_pgns/output.csv\n")
	for i := range matches {
		match := matches[i]
		if !match.Done || match.SpecialParams {
			continue
		}
		namePart := strconv.Itoa(int(match.TrainingRunID)) + "/" + strconv.Itoa(int(match.ID)) + ".pgn"
		filename := "match_pgns/" + namePart
		searchTarget := networkNums[match.CurrentBestID]
		possibleAnchors := anchors[match.TrainingRunID]
		anchorIdx := sort.Search(len(possibleAnchors), func(j int) bool { return possibleAnchors[j] > searchTarget }) - 1
		if anchorIdx < 0 {
			log.Println("Failed to find anchor for match: " + strconv.Itoa(int(match.ID)))
			log.Println("It will be ignored.")
			log.Println("Candidates:")
			for _, an := range possibleAnchors {
				log.Println(strconv.Itoa(int(an)))
			}
			log.Println("Searched for: " + strconv.Itoa(int(searchTarget)))
			continue
		}
		anchorMatches[match.TrainingRunID][anchorIdx] = append(anchorMatches[match.TrainingRunID][anchorIdx], filename)
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			continue
		}
		anchorsNew[match.TrainingRunID][anchorIdx] = true
		log.Println("Creating: " + filename)
		os.MkdirAll(filepath.Dir(filename), os.ModePerm)
		var games []db.MatchGame
		err := db.GetDB().Order("id").Where("match_id = ?", match.ID).Find(&games).Error
		if err != nil {
			return
		}
		var str strings.Builder
		for _, game := range games {
			if !game.Done {
				continue
			}
			first := match.CandidateID
			second := match.CurrentBestID
			rawResult := game.Result
			if game.Flip {
				second, first = first, second
				rawResult = -rawResult
			}
			second = networkNums[second]
			first = networkNums[first]
			result := "1/2-1/2"
			if rawResult == 1 {
				result = "1-0"
			} else if rawResult == -1 {
				result = "0-1"
			}
			str.WriteString("[Event \"lc0MG\"]\n")
			str.WriteString("[Site \"internet\"]\n")
			str.WriteString("[Date \"????.??.??\"]\n")
			str.WriteString("[Round \"-\"]\n")
			str.WriteString("[White \"lc0.net." + strconv.Itoa(int(first)) + "\"]\n")
			str.WriteString("[Black \"lc0.net." + strconv.Itoa(int(second)) + "\"]\n")
			str.WriteString("[Result \"" + result + "\"]\n")
			// If its a FEN start, specifiy variant chess960 to avoid python-chess assuming its not chess960 even though the fen isn't a legal position for normal chess.
			if strings.HasPrefix(game.Pgn, "[FEN ") {
				str.WriteString("[Variant \"chess960\"]\n")
			}
			str.WriteString(game.Pgn + "\n\n")
		}
		err = ioutil.WriteFile(filename, []byte(str.String()), 0644)
		if err != nil {
			return
		}
		ordoScript.WriteString("scripts/adjudicate.py --pgn match_pgns/" + namePart + " --output match_pgns/adj/" + namePart + " --syzygy /home/lc0/syzygy/3-4-5/:/home/lc0/syzygy/6-WDL/\n")
	}
	for run, _ := range anchors {
		for i, enabled := range anchorsNew[run] {
			if !enabled {
				continue
			}
			var matchList strings.Builder
			listname := "match_pgns/matchlist_" + strconv.Itoa(int(run)) + "_" + strconv.Itoa(int(i)) + ".list"
			outputname := "match_pgns/output_" + strconv.Itoa(int(run)) + "_" + strconv.Itoa(int(i)) + ".outputcsv"
			anchorName := "lc0.net." + strconv.Itoa(int(anchors[run][i]))
			anchorElo := strconv.FormatFloat(anchorElos[run][i], 'f', -1, 64)
			for _, name := range anchorMatches[run][i] {
				matchList.WriteString(name + "\n")
			}
			err = ioutil.WriteFile(listname, []byte(matchList.String()), 0644)
			if err != nil {
				log.Println("Failed to write matchList: " + listname)
				return
			}
			ordoScript.WriteString("~/ordo/ordo -G -Q -N 0 -D  -a " + anchorElo + " -A " + anchorName + " -W -n4  -V -U \"0,1\"  -c " + outputname + " -P " + listname + "\n")
			ordoScript.WriteString("cat " + outputname + " >> match_pgns/output.csv\n")
		}
	}
	err = ioutil.WriteFile("match_pgns/ordo.sh", []byte(ordoScript.String()), 0755)
	if err != nil {
		log.Println("Failed to write ordoScript.")
		return
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	//	s := single.New("prepapre_match_games")
	//	if err := s.CheckLock(); err != nil && err == single.ErrAlreadyRunning {
	//		log.Fatal("another instance of the app is already running, exiting")
	//	} else if err != nil {
	// Another error occurred, might be worth handling it as well
	//		log.Fatalf("failed to acquire exclusive app lock: %v", err)
	//	}
	//	defer s.TryUnlock()

	db.Init()
	defer db.Close()

	prepareMatches()
}
