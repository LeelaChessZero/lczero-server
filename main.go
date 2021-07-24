package main

import (
	"compress/gzip"
	"config"
	"crypto/sha256"
	"db"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PaesslerAG/gval"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-version"
	"github.com/jinzhu/gorm"
)

func checkUser(c *gin.Context) (*db.User, *db.Client, uint64, error) {
	if len(c.PostForm("user")) == 0 {
		return nil, nil, 0, errors.New("No user supplied")
	}
	splits := strings.SplitN(c.PostForm("user"), "/", 2)
	userName := splits[0]
	clientName := ""
	if len(splits) == 2 {
		clientName = splits[1]
	}
	if len(userName) > 32 {
		return nil, nil, 0, errors.New("Username too long")
	}
	if len(clientName) > 126 {
		return nil, nil, 0, errors.New("User client identifier too long")
	}
	if len(clientName) == 0 && len(c.PostForm("hostname")) != 0 {
		clientName = c.PostForm("hostname") + "_" + c.PostForm("gpu_id")
	}

	user := &db.User{
		Password: c.PostForm("password"),
	}
	err := db.GetDB().Where(db.User{Username: userName}).FirstOrCreate(&user).Error
	if err != nil {
		return nil, nil, 0, err
	}
	client := &db.Client{
		UserID:     user.ID,
		ClientName: clientName,
		GpuName:    c.PostForm("gpu"),
	}
	err = db.GetDB().Where(db.Client{UserID: user.ID, ClientName: clientName}).FirstOrCreate(&client).Error
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure passwords match
	if user.Password != c.PostForm("password") {
		return nil, nil, 0, errors.New("Incorrect password")
	}

	version, err := strconv.ParseUint(c.PostForm("version"), 10, 64)
	if err != nil {
		return nil, nil, 0, errors.New("Invalid version")
	}
	if version < config.Config.Clients.MinClientVersion {
		log.Printf("Rejecting old game from %s, version %d\n", user.Username, version)
		return nil, nil, 0, errors.New("you must upgrade to a newer version")
	}
	if version < config.Config.Clients.NextClientVersion {
		log.Printf("Would reject old game from %s, version %d with new threshold.\n", user.Username, version)
	}
	return user, client, version, nil
}

func nextGame(c *gin.Context) {
	user, _, _, err := checkUser(c)
	if err != nil {
		log.Println(strings.TrimSpace(err.Error()))
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	if user == nil {
		c.String(http.StatusBadRequest, "User load or create failed.")
		return
	}

	token, err := strconv.ParseInt(c.PostForm("token"), 10, 32)
	if err != nil {
		log.Println(user.Username)
		log.Println(strings.TrimSpace(err.Error()))
		c.String(http.StatusBadRequest, "Missing or invalid token field.")
		return
	}
	if token < 0 {
		token = 0
	}
	assignedID := uint(token) >> 16
	if assignedID == 0 {
		assignedID = user.AssignedTrainingRunID
		// Balance unassigneds a bit.
		if assignedID == 0 {
			if token >= 152000 {
				assignedID = 2
			}
		}
	}
	// If still not assigned, assign them to primary, which shall be assumed to be run 1.
	if assignedID == 0 {
		assignedID = 1
	}

	trainingRun := db.TrainingRun{
		Model:  gorm.Model{ID: assignedID},
		Active: true,
	}
	err = db.GetDB().Where(&trainingRun).First(&trainingRun).Error
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid training run")
		return
	}

	network := db.Network{}
	err = db.GetDB().Where("id = ?", trainingRun.BestNetworkID).First(&network).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error 1")
		return
	}

	var match []db.Match
	// Skip matches on request
	if !strings.Contains(c.PostForm("train_only"), "true") {
		ourSlice := token%3 + 1
		err = db.GetDB().Order("id").Preload("Candidate").Preload("CurrentBest").Where("done=false and training_run_id = ? and (target_slice = 0 or target_slice = ?)", trainingRun.ID, ourSlice).Limit(1).Find(&match).Error
		if err != nil {
			log.Println(err)
			c.String(500, "Internal error 2")
			return
		}
	}
	if len(match) > 0 {
		// Return this match
		matchGame := db.MatchGame{
			UserID:  user.ID,
			MatchID: match[0].ID,
		}
		err = db.GetDB().Create(&matchGame).Error
		// Note, this could cause an imbalance of white/black games for a particular match,
		// but it's good enough for now.
		flip := (matchGame.ID & 1) == 1
		db.GetDB().Model(&matchGame).Update("flip", flip)
		if err != nil {
			log.Println(err)
			c.String(500, "Internal error 3")
			return
		}
		result := gin.H{
			"type":         "match",
			"matchGameId":  matchGame.ID,
			"sha":          match[0].CurrentBest.Sha,
			"candidateSha": match[0].Candidate.Sha,
			"params":       match[0].Parameters,
			"bookUrl":      trainingRun.MatchBook,
			"flip":         flip,
		}
		c.JSON(http.StatusOK, result)
		return
	}
	if trainingRun.MultiNetMode {
		otherNetwork := network
		offset := ((network.NetworkNumber * 33) ^ uint(token)) % 20
		var prevNetwork db.Network
		err = db.GetDB().Where("network_number = ?", network.NetworkNumber-offset).First(&prevNetwork).Error
		if err == nil {
			otherNetwork = prevNetwork
		}

		result := gin.H{
			"type":         "train",
			"trainingId":   trainingRun.ID,
			"networkId":    trainingRun.BestNetworkID,
			"params":       trainingRun.TrainParameters,
			"sha":          network.Sha,
			"candidateSha": otherNetwork.Sha,
			"bookUrl":      trainingRun.TrainBook,
			"keepTime":     "16h",
		}
		c.JSON(http.StatusOK, result)
	} else {
		result := gin.H{
			"type":       "train",
			"trainingId": trainingRun.ID,
			"networkId":  trainingRun.BestNetworkID,
			"params":     trainingRun.TrainParameters,
			"sha":        network.Sha,
			"bookUrl":    trainingRun.TrainBook,
			"keepTime":   "16h",
		}
		c.JSON(http.StatusOK, result)
	}
}

// Computes SHA256 of gzip compressed file
func computeSha(httpFile *multipart.FileHeader) (string, error) {
	h := sha256.New()
	file, err := httpFile.Open()
	if err != nil {
		return "", err
	}
	defer file.Close()

	zr, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, zr); err != nil {
		return "", err
	}
	sha := fmt.Sprintf("%x", h.Sum(nil))
	if len(sha) != 64 {
		return "", errors.New("Hash length is not 64")
	}

	return sha, nil
}

func getTrainingRun(trainingID uint) (*db.TrainingRun, error) {
	var trainingRun db.TrainingRun
	err := db.GetDB().Where("id = ?", trainingID).First(&trainingRun).Error
	if err != nil {
		return nil, err
	}
	return &trainingRun, nil
}

func createMatch(trainingRun *db.TrainingRun, targetSlice int, network *db.Network, testonly bool, params string) error {
	gameCap := config.Config.Matches.Games
	if targetSlice == 0 {
		gameCap *= 5
	}
	match := db.Match{
		TrainingRunID: trainingRun.ID,
		CandidateID:   network.ID,
		CurrentBestID: trainingRun.BestNetworkID,
		Done:          false,
		GameCap:       gameCap,
		Parameters:    params,
		TargetSlice:   targetSlice,
	}
	if testonly {
		match.TestOnly = true
	}
	return db.GetDB().Create(&match).Error
}

func uploadNetwork(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		log.Println(err.Error())
		c.String(http.StatusBadRequest, "Missing file")
		return
	}
	written := false
	tempFileName := ""
	sha := ""
	prevNetSha := c.PostForm("prev_delta_sha")
	if prevNetSha != "" {
		prevNetwork := db.Network{
			Sha: prevNetSha,
		}

		// Check for existing network
		err := db.GetDB().Where(&prevNetwork).First(&prevNetwork).Error
		if err != nil {
			log.Println(err)
			c.String(400, "Unknown previous network")
			return
		}
		if _, err := os.Stat(prevNetwork.Path); os.IsNotExist(err) {
			c.String(400, "Previous network missing")
			return
		}
		h := sha256.New()
		prevReader, err := os.Open(prevNetwork.Path)
		if err != nil {
			c.String(400, "Couldn't open previous network")
			return
		}
		defer prevReader.Close()
		deltaReader, err := file.Open()
		if err != nil {
			c.String(400, "Couldn't open delta stream")
			return
		}
		defer deltaReader.Close()

		zrPrev, err := gzip.NewReader(prevReader)
		if err != nil {
			c.String(400, "Previous network corrupt")
			return
		}
		zrDelta, err := gzip.NewReader(deltaReader)
		if err != nil {
			c.String(400, "Delta corrupt")
			return
		}
		writer, err := ioutil.TempFile("", "deltaworkfile")
		tempFileName = writer.Name()
		defer os.Remove(tempFileName)
		defer writer.Close()

		prevData, err := ioutil.ReadAll(zrPrev)
		if err != nil {
			c.String(400, "Read prev failed.")
			return
		}
		deltaData, err := ioutil.ReadAll(zrDelta)
		if err != nil {
			c.String(400, "Read delta failed.")
			return
		}
		if len(prevData) != len(deltaData) {
			c.String(400, "Data lengths don't match.")
			return
		}
		for i := 0; i < len(prevData); i++ {
			prevData[i] ^= deltaData[i]
		}
		_, err = h.Write(prevData)
		if err != nil {
			c.String(400, "Failed to write data to sha.")
			return
		}
		zwTemp := gzip.NewWriter(writer)
		defer zwTemp.Close()
		_, err = zwTemp.Write(prevData)
		if err != nil {
			c.String(400, "Failed to write data to tempFile.")
			return
		}
		zwTemp.Close()
		writer.Close()
		sha = fmt.Sprintf("%x", h.Sum(nil))
		if len(sha) != 64 {
			c.String(400, "Sha failed")
			return
		}
		written = true
	} else {

		// Compute hash of network
		sha, err = computeSha(file)
		if err != nil {
			log.Println(err.Error())
			c.String(500, "Internal error")
			return
		}
	}

	network := db.Network{
		Sha: sha,
	}

	// Check for existing network
	var networkCount int
	err = db.GetDB().Model(&network).Where(&network).Count(&networkCount).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	if networkCount > 0 {
		c.String(http.StatusBadRequest, "Network already exists")
		return
	}

	// Create new network
	trainingRunID, err := strconv.ParseUint(c.PostForm("training_id"), 10, 32)
	// If not provided, assume its for the main run.
	if err != nil || trainingRunID == 0 {
		trainingRunID = 1
	}
	network.TrainingRunID = uint(trainingRunID)
	trainingRun, err := getTrainingRun(uint(trainingRunID))
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	// Atomic network display number increment and acquire.
	rows, err := db.GetDB().Raw("WITH updated AS (UPDATE training_runs SET last_network = last_network + 1 WHERE id = ? RETURNING last_network) SELECT * FROM updated", uint(trainingRunID)).Rows()
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	{
		defer rows.Close()
		for rows.Next() {
			var nextNetworkNumber uint
			rows.Scan(&nextNetworkNumber)
			network.NetworkNumber = nextNetworkNumber
		}
	}
	layers, err := strconv.ParseInt(c.PostForm("layers"), 10, 32)
	network.Layers = int(layers)
	filters, err := strconv.ParseInt(c.PostForm("filters"), 10, 32)
	network.Filters = int(filters)
	err = db.GetDB().Create(&network).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	err = db.GetDB().Model(&network).Update("path", filepath.Join("networks", network.Sha)).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	os.MkdirAll(filepath.Dir(network.Path), os.ModePerm)

	if !written {
		// Save the file
		if err := c.SaveUploadedFile(file, network.Path); err != nil {
			log.Println(err.Error())
			c.String(500, "Saving file")
			return
		}
	} else {
		tempFileData, err := ioutil.ReadFile(tempFileName)
		if err != nil {
			c.String(500, "Can't open temp file to copy.")
			return
		}
		err = ioutil.WriteFile(network.Path, tempFileData, 0644)
		if err != nil {
			c.String(500, "Can't copy to network file.")
			return
		}
	}

	// TODO(gary): Make this more generic - upload to s3 for now
	cmdParams := config.Config.URLs.OnNewNetwork
	if len(cmdParams) > 0 {
		for i := range cmdParams {
			if cmdParams[i] == "%NETWORK_PATH%" {
				cmdParams[i] = network.Path
			}
		}

		cmd := exec.Command(cmdParams[0], cmdParams[1:]...)
		err = cmd.Run()
		if err != nil {
			log.Println(err.Error())
			c.String(500, "Uploading to s3")
			return
		}
	}

	matchParams := trainingRun.MatchParameters
	if matchParams == "" {
		params, err := json.Marshal(config.Config.Matches.Parameters)
		if err != nil {
			log.Println(err)
			c.String(500, "Internal error")
			return
		}
		matchParams = string(params[:])
	}
	// Create a match to see if this network is better
	var bestNetwork db.Network
	err = db.GetDB().Where("id = ?", trainingRun.BestNetworkID).First(&bestNetwork).Error
	if err != nil {
		log.Println(err)
		// No valid best network, but it has uploaded successfully.
		c.String(http.StatusOK, fmt.Sprintf("Network %s uploaded successfully, remember to manually set it as best.", network.Sha))
		return
	}

	err = createMatch(trainingRun, 1, &network, c.DefaultPostForm("testonly", "0") == "1", matchParams)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	// Regression tests for current best.  Done here because the 'end of match' code logic isn't thread safe, so could create matches multiple times.
	var prevNetwork1 db.Network
	err = db.GetDB().Where("network_number = ?", bestNetwork.NetworkNumber-3).First(&prevNetwork1).Error
	if err == nil {
		createMatch(trainingRun, 2, &prevNetwork1, true, matchParams)
	}
	var prevNetwork2 db.Network
	err = db.GetDB().Where("network_number = ?", bestNetwork.NetworkNumber-10).First(&prevNetwork2).Error
	if err == nil {
		createMatch(trainingRun, 3, &prevNetwork2, true, matchParams)
	}
	if bestNetwork.NetworkNumber%15 == 0 {
		var prevNetwork2 db.Network
		err = db.GetDB().Where("network_number = ?", bestNetwork.NetworkNumber-30).First(&prevNetwork2).Error
		if err == nil {
			createMatch(trainingRun, 0, &prevNetwork2, true, matchParams)
		}
	}
	if bestNetwork.NetworkNumber%25 == 0 {
		var prevNetwork2 db.Network
		err = db.GetDB().Where("network_number = ?", bestNetwork.NetworkNumber-100).First(&prevNetwork2).Error
		if err == nil {
			createMatch(trainingRun, 0, &prevNetwork2, true, matchParams)
		}
	}
	if bestNetwork.NetworkNumber%75 == 0 {
		var prevNetwork2 db.Network
		err = db.GetDB().Where("network_number = ?", bestNetwork.NetworkNumber-300).First(&prevNetwork2).Error
		if err == nil {
			createMatch(trainingRun, 0, &prevNetwork2, true, matchParams)
		}
	}

	c.String(http.StatusOK, fmt.Sprintf("Network %s uploaded successfully.", network.Sha))
}

func checkEngineVersion(engineVersion string, username string, training_id uint) bool {
	if training_id == 3 {
		return true
	}
	v, err := version.NewVersion(engineVersion)
	if err != nil {
		return false
	}
	target_soft, err := version.NewVersion(config.Config.Clients.NextEngineVersion)
	if err != nil {
		log.Println("Invalid comparison version, rejecting all clients!!!")
		return false
	}
	if strings.HasSuffix(engineVersion, "-dev") {
		if username == "Teststuff" {
			return true
		}
		log.Printf("%s is rejected for using dev version.", username)
		return false
	}
	if v.Compare(target_soft) < 0 {
		log.Printf("%s would be rejected with proposed threshold.", username)
	}
	target, err := version.NewVersion(config.Config.Clients.MinEngineVersion)
	if err != nil {
		log.Println("Invalid comparison version, rejecting all clients!!!")
		return false
	}
	return v.Compare(target) >= 0
}

func checkPermissionExpr(expr string, user db.User, trainingRunId uint64, engineVersion string, clientVersion string) bool {
	if expr == "" {
		return true
	}
	v, err := version.NewVersion(engineVersion)
	if err != nil {
		return false
	}
	version, err := strconv.ParseUint(clientVersion, 10, 64)
	if err != nil {
		return false
	}
	value, err := gval.Evaluate(expr, map[string]interface{}{
		"username":        user.Username,
		"assigned_run_id": user.AssignedTrainingRunID,
		"training_run":    trainingRunId,
		"engine_suffix":   v.Prerelease(),
		"engine_major":    v.Segments()[0],
		"engine_minor":    v.Segments()[1],
		"engine_patch":    v.Segments()[2],
		"client_version":  version,
	})
	if err != nil {
		log.Println("Invalid expression: ", expr)
		return false
	}
	return value.(bool)
}

func uploadGame(c *gin.Context) {
	user, client, version, err := checkUser(c)
	if err != nil {
		log.Println(strings.TrimSpace(err.Error()))
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	client.LastVersion = uint(version)
	client.LastEngineVersion = c.PostForm("engineVersion")
	client.LastGameAt = time.Now()
	client.GpuName = c.PostForm("gpu")
	training_id, err := strconv.ParseUint(c.PostForm("training_id"), 10, 32)
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid training_id")
	}
	if !checkEngineVersion(c.PostForm("engineVersion"), user.Username, uint(training_id)) {
		log.Printf("Rejecting game with old lczero version %s", c.PostForm("engineVersion"))
		c.String(http.StatusBadRequest, "\n\n\n\n\nYou must upgrade to a newer lczero version!!\n\n\n\n\n")
		return
	}

	training_run, err := getTrainingRun(uint(training_id))
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	if !checkPermissionExpr(training_run.PermissionExpr, *user, training_id, c.PostForm("engineVersion"), c.PostForm("version")) {
		log.Println("Request doesn't match the expression: ", training_run.PermissionExpr)
		c.String(http.StatusBadRequest, "Contribution to this training run is not allowed for this client. (You need to upgrade or downgraded something.)")
		return
	}

	network_id, err := strconv.ParseUint(c.PostForm("network_id"), 10, 32)
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid network_id")
		return
	}
	resign_fp_threshold, err := strconv.ParseFloat(c.PostForm("fp_threshold"), 64)
	if err != nil {
		resign_fp_threshold = -1
	}

	var network db.Network
	err = db.GetDB().Where("id = ?", network_id).First(&network).Error
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid network")
		return
	}

	err = db.GetDB().Exec("UPDATE networks SET games_played = games_played + 1 WHERE id = ?", network_id).Error
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Internal error")
		return
	}

	// Source
	file, err := c.FormFile("file")
	if err != nil {
		log.Println(err.Error())
		c.String(http.StatusBadRequest, "Missing file")
		return
	}
	if file.Size <= 0 {
		log.Println("Zero sized upload received.")
		c.String(http.StatusBadRequest, "Zero length file")
		return
	}

	// Atomic network game run sequence number increment and acquire.
	rows, err := db.GetDB().Raw("WITH updated AS (UPDATE training_runs SET last_game = last_game + 1 WHERE id = ? RETURNING last_game) SELECT * FROM updated", uint(training_id)).Rows()
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	var nextGameNumber uint
	nextGameNumber = 0
	{
		defer rows.Close()
		for rows.Next() {
			rows.Scan(&nextGameNumber)
		}
	}
	if nextGameNumber == 0 {
		log.Println("Couldn't get a new game number.'")
		c.String(500, "Internal error")
		return
	}

	// Create new game
	game := db.TrainingGame{
		UserID:            user.ID,
		ClientID:          client.ID,
		TrainingRunID:     training_run.ID,
		NetworkID:         network.ID,
		Version:           uint(version),
		EngineVersion:     c.PostForm("engineVersion"),
		ResignFPThreshold: resign_fp_threshold,
		GameNumber:        nextGameNumber,
	}
	err = db.GetDB().Create(&game).Error
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Internal error")
		return
	}
	err = db.GetDB().Save(&client).Error
	if err != nil {
		// Only log error, not worth blocking uploads if this fails.
		log.Println(err)
	}

	game_path := filepath.Join("games", fmt.Sprintf("run%d/training.%d.gz", training_run.ID, nextGameNumber))

	os.MkdirAll(filepath.Dir(game_path), os.ModePerm)

	// Save the file
	if err := c.SaveUploadedFile(file, game_path); err != nil {
		log.Println(err.Error())
		c.String(500, "Saving file")
		return
	}

	// Save pgn
	pgn_path := fmt.Sprintf("pgns/run%d/%d.pgn", training_run.ID, nextGameNumber)
	os.MkdirAll(filepath.Dir(pgn_path), os.ModePerm)
	err = ioutil.WriteFile(pgn_path, []byte(c.PostForm("pgn")), 0644)
	if err != nil {
		log.Println(err.Error())
		c.String(500, "Saving pgn")
		return
	}
	// Save resign rate
        s := fmt.Sprintf("%f", resign_fp_threshold)
        if (s == "-1.000000") {
                return 
        } else {
                resign_path := fmt.Sprintf("resign/run%d/%d.txt", training_run.ID, nextGameNumber)
                os.MkdirAll(filepath.Dir(resign_path), os.ModePerm)
                err = ioutil.WriteFile(resign_path, []byte(s), 0644)
                if err != nil {
                        log.Println(err.Error())
                        c.String(500, "Saving resign file")
                        return
                        }
                }


	c.String(http.StatusOK, fmt.Sprintf("File %s uploaded successfully with fields user=%s.", file.Filename, user.Username))
}

func getNetwork(c *gin.Context) {
	// lczero.org/cached/ is behind the cloudflare CDN.  Redirect to there to ensure
	// we hit the CDN.
	c.Redirect(http.StatusMovedPermanently, config.Config.URLs.NetworkLocation+c.Query("sha"))
}

func cachedGetNetwork(c *gin.Context) {
	network := db.Network{
		Sha: c.Param("sha"),
	}

	// Check for existing network
	err := db.GetDB().Where(&network).First(&network).Error
	if err != nil {
		log.Println(err)
		c.String(400, "Unknown network")
		return
	}
	if _, err := os.Stat(network.Path); os.IsNotExist(err) {
		backup_location := config.Config.URLs.BackupNetworkLocation
		if backup_location != "" {
			c.Redirect(http.StatusMovedPermanently, backup_location+c.Param("sha"))
		} else {
			c.String(400, "Network missing")
		}
		return
	}

	// Serve the file
	c.File(network.Path)
}

func setBestNetwork(training_id uint, network_id uint) error {
	// Set the best network of this training_run
	training_run, err := getTrainingRun(training_id)
	if err != nil {
		return err
	}
	err = db.GetDB().Model(&training_run).Update("best_network_id", network_id).Error
	if err != nil {
		return err
	}
	return nil
}

func checkMatchFinished(match_id uint) error {
	// Now check to see if match is finished
	var match db.Match
	err := db.GetDB().Where("id = ?", match_id).First(&match).Error
	if err != nil {
		return err
	}

	// Already done?  Just return
	if match.Done {
		return nil
	}

	if match.Wins+match.Losses+match.Draws >= match.GameCap {
		err = db.GetDB().Model(&match).Update("done", true).Error
		if err != nil {
			return err
		}
		if match.TestOnly {
			return nil
		}
		// Update to our new best network
		// TODO(SPRT)
		passed := calcElo(match.Wins, match.Losses, match.Draws) > config.Config.Matches.Threshold
		err = db.GetDB().Model(&match).Update("passed", passed).Error
		if err != nil {
			return err
		}
		if passed {
			err = setBestNetwork(match.TrainingRunID, match.CandidateID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func matchResult(c *gin.Context) {
	user, _, version, err := checkUser(c)
	if err != nil {
		log.Println(strings.TrimSpace(err.Error()))
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	match_game_id, err := strconv.ParseUint(c.PostForm("match_game_id"), 10, 32)
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid match_game_id")
		return
	}

	var match_game db.MatchGame
	err = db.GetDB().Where("id = ?", match_game_id).First(&match_game).Error
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid match_game")
		return
	}

	var match db.Match
	err = db.GetDB().Where("id = ?", match_game.MatchID).First(&match).Error
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Invalid match_game, no matching match.")
		return
	}

	if !checkEngineVersion(c.PostForm("engineVersion"), user.Username, uint(match.TrainingRunID)) {
		log.Printf("Rejecting game with old lczero version %s", c.PostForm("engineVersion"))
		c.String(http.StatusBadRequest, "\n\n\n\n\nYou must upgrade to a newer lczero version!!\n\n\n\n\n")
		return
	}

	result, err := strconv.ParseInt(c.PostForm("result"), 10, 32)
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, "Unable to parse result")
		return
	}

	good_result := result == 0 || result == -1 || result == 1
	if !good_result {
		c.String(http.StatusBadRequest, "Bad result")
		return
	}

	err = db.GetDB().Model(&match_game).Updates(db.MatchGame{
		Version:       uint(version),
		Result:        int(result),
		Done:          true,
		Pgn:           c.PostForm("pgn"),
		EngineVersion: c.PostForm("engineVersion"),
	}).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	col := ""
	if result == 0 {
		col = "draws"
	} else if result == 1 {
		col = "wins"
	} else {
		col = "losses"
	}
	// Atomic update of game count
	err = db.GetDB().Exec(fmt.Sprintf("UPDATE matches SET %s = %s + 1 WHERE id = ?", col, col), match_game.MatchID).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	err = checkMatchFinished(match_game.MatchID)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	c.String(http.StatusOK, fmt.Sprintf("Match game %d successfuly uploaded from user=%s.", match_game.ID, user.Username))
}

func getActiveUsers(userLimit int) (gin.H, error) {
	rows, err := db.GetDB().Raw(`SELECT user_id, username, MAX(version), MAX(SPLIT_PART(engine_version, '.', 2) :: INTEGER), MAX(training_games.created_at), count(*), count(*) FILTER (WHERE training_run_id = 1) as count_run1, assigned_training_run_id FROM training_games
LEFT JOIN users
ON users.id = training_games.user_id
WHERE training_games.created_at >= now() - INTERVAL '1 day'
GROUP BY user_id, username, assigned_training_run_id
ORDER BY count DESC`).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	active_users := 0
	games_played := 0
	users_json := []gin.H{}
	for rows.Next() {
		var user_id uint
		var username string
		var version int
		var engine_version string
		var created_at time.Time
		var count uint64
		var count_run1 uint64
		var assigned_training_run_id uint
		rows.Scan(&user_id, &username, &version, &engine_version, &created_at, &count, &count_run1, &assigned_training_run_id)

		active_users += 1
		games_played += int(count)

		if len(username) > 32 {
			username = username[0:32] + "..."
		}

		if userLimit == -1 || active_users <= userLimit {
			users_json = append(users_json, gin.H{
				"user":                     username,
				"games_today":              count,
				"games_today_1":            count_run1,
				"system":                   "",
				"version":                  version,
				"engine":                   engine_version,
				"last_updated":             created_at.Format("2006-01-02 15:04:05 -07:00"),
				"assigned_training_run_id": assigned_training_run_id,
			})
		}
	}

	result := gin.H{
		"active_users": active_users,
		"games_played": games_played,
		"users":        users_json,
	}
	return result, nil
}

func calcEloAndError(wins, losses, draws int) (elo, errorMargin float64) {
	n := wins + losses + draws
	w := float64(wins) / float64(n)
	l := float64(losses) / float64(n)
	d := float64(draws) / float64(n)
	mu := w + d/2

	devW := w * math.Pow(1.-mu, 2.)
	devL := l * math.Pow(0.-mu, 2.)
	devD := d * math.Pow(0.5-mu, 2.)
	stdev := math.Sqrt(devD+devL+devW) / math.Sqrt(float64(n))

	delta := func(p float64) float64 {
		return -400. * math.Log10(1/p-1)
	}

	erfInv := func(x float64) float64 {
		a := 8. * (math.Pi - 3.) / (3. * math.Pi * (4. - math.Pi))
		y := math.Log(1. - x*x)
		z := 2./(math.Pi*a) + y/2.

		ret := math.Sqrt(math.Sqrt(z*z-y/a) - z)
		if x < 0. {
			return -ret
		}
		return ret
	}

	phiInv := func(p float64) float64 {
		return math.Sqrt(2) * erfInv(2.*p-1.)
	}

	muMin := mu + phiInv(0.025)*stdev
	muMax := mu + phiInv(0.975)*stdev

	elo = delta(mu)
	errorMargin = (delta(muMax) - delta(muMin)) / 2.

	return
}

func calcElo(wins, losses, draws int) float64 {
	elo, _ := calcEloAndError(wins, losses, draws)
	return elo
}

func calcEloError(wins, losses, draws int) float64 {
	_, error := calcEloAndError(wins, losses, draws)
	return error
}

func getProgress(trainingRunID uint) ([]gin.H, map[uint]float64, error) {
	elos := make(map[uint]float64)

	var matches []db.Match
	err := db.GetDB().Order("id").Where("training_run_id=?", trainingRunID).Find(&matches).Error
	if err != nil {
		return nil, elos, err
	}

	var networks []db.Network
	err = db.GetDB().Order("id").Where("training_run_id=?", trainingRunID).Find(&networks).Error
	if err != nil {
		return nil, elos, err
	}

	counts := getNetworkCounts(networks)

	result := []gin.H{}
	result = append(result, gin.H{
		"net":    0,
		"rating": 0.0,
		"best":   false,
		"sprt":   "???",
		"id":     "",
		"anchor": true,
	})
	result = append(result, gin.H{
		"net":    0,
		"rating": 0.0,
		"best":   false,
		"sprt":   "FAIL",
		"id":     "",
		"anchor": true,
	})
	var count uint64 = 0
	var elo float64 = 0.0
	var matchIdx int = 0
	firstNet := true
	for _, network := range networks {
		var sprt string = "???"
		var best bool = false
		eloResolved := false
		for matchIdx < len(matches) && (matches[matchIdx].CandidateID == network.ID || matches[matchIdx].TestOnly) {
			if matches[matchIdx].TestOnly && network.EloSet {
				matchIdx += 1
				continue
			}
			matchElo := calcElo(matches[matchIdx].Wins, matches[matchIdx].Losses, matches[matchIdx].Draws)
			if matches[matchIdx].Done {
				if matches[matchIdx].TestOnly {
					sprt = "???"
					best = false
				} else if matches[matchIdx].Passed {
					sprt = "PASS"
					best = true
				} else {
					sprt = "FAIL"
					best = false
				}
			}
			if math.IsNaN(matchElo) {
				matchElo = 0.0
			}
			nextElo := elo + matchElo
			if !matches[matchIdx].TestOnly && matches[matchIdx].Passed {
				if network.EloSet {
					nextElo = network.Elo
				}
				elo = nextElo
			}
			result = append(result, gin.H{
				"net":    count,
				"rating": nextElo,
				"best":   best,
				"sprt":   sprt,
				"id":     network.NetworkNumber,
				"anchor": network.Anchor,
			})
			eloResolved = true
			matchIdx += 1
		}
		// Sometimes a network is never a candidate - especially true for anchors.
		// Here create an output if that happens.
		if !eloResolved && network.EloSet && !firstNet && network.Anchor {
			result = append(result, gin.H{
				"net":    count,
				"rating": network.Elo,
				"best":   network.Anchor,
				"sprt":   "PASS",
				"id":     network.NetworkNumber,
				"anchor": network.Anchor,
			})
			elo = network.Elo
		}
		if counts[network.ID] == 0 {
			count += 1
		}
		count += counts[network.ID]
		elos[network.ID] = elo
		firstNet = false
	}

	return result, elos, nil
}

func filterProgressToAnchor(result []gin.H) []gin.H {
	i := len(result) - 1
	for ; i > 0; i -= 1 {
		str := fmt.Sprintf("%v", result[i]["anchor"])
		if str == "true" {
			break
		}
	}
	// Show just the last 100 networks
	result = result[i:]

	// Ensure the ordering is correct now (HACK)
	tmp := []gin.H{}
	tmp = append(tmp, gin.H{
		"net":    result[0]["net"],
		"rating": result[0]["rating"],
		"best":   false,
		"sprt":   "???",
		"id":     "",
	})
	tmp = append(tmp, gin.H{
		"net":    result[0]["net"],
		"rating": result[0]["rating"],
		"best":   false,
		"sprt":   "FAIL",
		"id":     "",
	})

	return append(tmp, result...)
}

func filterProgress(result []gin.H, limit int) []gin.H {
	// Show just the last limit networks
	if len(result) > limit {
		result = result[len(result)-limit:]
	}

	// Ensure the ordering is correct now (HACK)
	tmp := []gin.H{}
	tmp = append(tmp, gin.H{
		"net":    result[0]["net"],
		"rating": result[0]["rating"],
		"best":   false,
		"sprt":   "???",
		"id":     "",
	})
	tmp = append(tmp, gin.H{
		"net":    result[0]["net"],
		"rating": result[0]["rating"],
		"best":   false,
		"sprt":   "FAIL",
		"id":     "",
	})

	return append(tmp, result...)
}

func viewActiveUsers(c *gin.Context) {
	users, err := getActiveUsers(-1)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	c.HTML(http.StatusOK, "active_users", gin.H{
		"active_users": users["active_users"],
		"games_played": users["games_played"],
		"Users":        users["users"],
	})
}

func getTopUsers(table string) ([]gin.H, error) {
	type Result struct {
		Username string
		Count    int
	}

	var result []Result
	err := db.GetDB().Table(table).Select("username, count").Order("count desc").Limit(50).Scan(&result).Error
	if err != nil {
		return nil, err
	}

	users_json := []gin.H{}
	for _, user := range result {
		users_json = append(users_json, gin.H{
			"user":        user.Username,
			"games_today": user.Count,
		})
	}
	return users_json, nil
}

func frontPage(c *gin.Context) {
	users, err := getActiveUsers(50)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	// TODO: support showing other runs progress graph on front page?
	progress, _, err := getProgress(1)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	if c.DefaultQuery("full_elo", "0") == "0" {
		progress = filterProgress(progress, 100)
	}

	// TODO: support showing other runs progress bar on front page?
	network := db.Network{
		TrainingRunID: 1,
	}
	err = db.GetDB().Where(&network).Last(&network).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	trainPercent := int(math.Min(100.0, float64(network.GamesPlayed)/40000.0*100.0))

	topUsersMonth, err := getTopUsers("games_month")
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	topUsers, err := getTopUsers("games_all")
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	c.HTML(http.StatusOK, "index", gin.H{
		"active_users":    users["active_users"],
		"games_played":    users["games_played"],
		"top_users_day":   users["users"],
		"top_users_month": topUsersMonth,
		"top_users":       topUsers,
		"progress":        progress,
		"train_percent":   trainPercent,
		"progress_info":   fmt.Sprintf("%d/32000", network.GamesPlayed),
	})
}

func user(c *gin.Context) {
	name := c.Param("name")
	user := db.User{
		Username: name,
	}
	err := db.GetDB().Where(&user).First(&user).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	clients := []db.Client{}
	err = db.GetDB().Model(&user).Order("created_at DESC").Related(&clients).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	clientJson := []gin.H{}
	for _, client := range clients {
		presentationName := client.ClientName
		if len(presentationName) == 0 {
			presentationName = "<default>"
		}
		clientJson = append(clientJson, gin.H{
			"user":           user.Username,
			"client":         client.ClientName,
			"client_name":    presentationName,
			"client_version": client.LastVersion,
			"engine_version": client.LastEngineVersion,
			"last_game":      client.LastGameAt.Format("2006-01-02 15:04:05 -07:00"),
			"client_gpu":     client.GpuName,
		})
	}

	c.HTML(http.StatusOK, "user", gin.H{
		"user":    user.Username,
		"clients": clientJson,
	})
}

func client(c *gin.Context) {
	name := c.Param("name")
	user := db.User{
		Username: name,
	}
	err := db.GetDB().Where(&user).First(&user).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	clientName := c.Param("client_name")
	client := db.Client{
		UserID:     user.ID,
		ClientName: clientName,
	}
	err = db.GetDB().Where(&client).First(&client).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	games := []db.TrainingGame{}
	err = db.GetDB().Model(&client).Preload("Network").Limit(50).Order("created_at DESC").Where("created_at > CURRENT_DATE - 2").Related(&games).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	gamesJson := []gin.H{}
	for _, game := range games {
		gamesJson = append(gamesJson, gin.H{
			"id":         game.ID,
			"created_at": game.CreatedAt.Format("2006-01-02 15:04:05 -07:00"),
			"network":    game.Network.Sha,
		})
	}

	c.HTML(http.StatusOK, "client", gin.H{
		"user":   user.Username,
		"client": client.ClientName,
		"games":  gamesJson,
	})
}

func game(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	game := db.TrainingGame{
		ID: uint64(id),
	}
	err = db.GetDB().Where(&game).First(&game).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	pgn, err := ioutil.ReadFile(fmt.Sprintf("pgns/run%d/%d.pgn", game.TrainingRunID, game.GameNumber))
	if err != nil {
		log.Println(err)
		if os.IsNotExist(err) {
			c.Redirect(http.StatusMovedPermanently, "/game_moved")
		} else {
			c.String(500, "Internal error")
		}
		return
	}

	c.HTML(http.StatusOK, "game", gin.H{
		"pgn": string(pgn),
	})
}

func viewMatchGame(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	game := db.MatchGame{
		ID: uint64(id),
	}
	err = db.GetDB().Where(&game).First(&game).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	c.HTML(http.StatusOK, "game", gin.H{
		"pgn": strings.Replace(game.Pgn, "e.p.", "", -1),
	})
}

func getNetworkCounts(networks []db.Network) map[uint]uint64 {
	counts := make(map[uint]uint64)
	for _, network := range networks {
		counts[network.ID] = uint64(network.GamesPlayed)
	}
	return counts
}

func viewNetworks(c *gin.Context) {
	var networks []db.Network
	var err error
	run := c.Param("run")
	run = strings.TrimPrefix(run, "/")
	if run == "" {
		err = db.GetDB().Order("id desc").Find(&networks).Error
	} else {
		err = db.GetDB().Order("id desc").Where("training_run_id = ?", run).Find(&networks).Error
	}
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	allElos := make(map[uint]float64)
	trainingRunIDs := make(map[uint]bool)
	for _, network := range networks {
		if !trainingRunIDs[network.TrainingRunID] {
			trainingRunIDs[network.TrainingRunID] = true
			_, elos, err := getProgress(network.TrainingRunID)
			if err != nil {
				log.Println(err)
				c.String(500, "Internal error")
				return
			}
			for k, v := range elos {
				allElos[k] = v
			}
		}
	}

	counts := getNetworkCounts(networks)
	json := []gin.H{}
	if c.DefaultQuery("show_all", "1") == "0" {
		networks = networks[0:99]
	}
	for _, network := range networks {
		json = append(json, gin.H{
			"id":          network.ID,
			"number":      network.NetworkNumber,
			"training_id": network.TrainingRunID,
			"elo":         fmt.Sprintf("%.2f", allElos[network.ID]),
			"games":       counts[network.ID],
			"sha":         network.Sha,
			"short_sha":   network.Sha[0:8],
			"blocks":      network.Layers,
			"filters":     network.Filters,
			"created_at":  network.CreatedAt.Format("2006-01-02 15:04:05 -07:00"),
			"real_elo":    network.Elo,
		})
	}

	c.HTML(http.StatusOK, "networks", gin.H{
		"networks": json,
	})
}

func viewTrainingRuns(c *gin.Context) {
	training_runs := []db.TrainingRun{}
	err := db.GetDB().Preload("BestNetwork").Find(&training_runs).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	rows := []gin.H{}
	for _, training_run := range training_runs {
		match_params := training_run.MatchParameters
		if match_params == "" {
			params, err := json.Marshal(config.Config.Matches.Parameters)
			if err != nil {
				log.Println(err)
				c.String(500, "Internal error")
				return
			}
			match_params = string(params[:])
		}
		rows = append(rows, gin.H{
			"id":          training_run.ID,
			"active":      training_run.Active,
			"trainParams": training_run.TrainParameters,
			"matchParams": match_params,
			"bestNetwork": training_run.BestNetwork.NetworkNumber,
			"description": training_run.Description,
		})
	}

	c.HTML(http.StatusOK, "training_runs", gin.H{
		"training_runs": rows,
	})
}

func viewTrainingRun(c *gin.Context) {
	run, err := strconv.ParseUint(c.Param("run"), 10, 64)
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	progress, _, err := getProgress(uint(run))
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	full := true
	if c.DefaultQuery("show_less", "0") == "1" {
		progress = filterProgress(progress, 50)
		full = false
	}
	if c.DefaultQuery("full_elo", "0") == "0" {
		progress = filterProgress(progress, 100)
		full = false
	}
	if c.DefaultQuery("to_last_anchor", "1") == "1" {
		progress = filterProgressToAnchor(progress)
		full = false
	}

	c.HTML(http.StatusOK, "training_run", gin.H{
		"run":      run,
		"progress": progress,
		"full":     full,
	})
}

func viewStats(c *gin.Context) {
	// TODO: should this be 3 nets per training run?
	var networks []db.Network
	err := db.GetDB().Order("id desc").Where("games_played > 0").Limit(3).Find(&networks).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	json := []gin.H{}
	for _, network := range networks {
		json = append(json, gin.H{
			"short_sha": network.Sha[0:8],
		})
	}

	c.HTML(http.StatusOK, "stats", gin.H{
		"networks": json,
	})
}

func viewMatches(c *gin.Context) {
	var matches []db.Match
	var err error
	run := c.Param("run")
	run = strings.TrimPrefix(run, "/")
	if run == "" {
		err = db.GetDB().Order("id desc").Find(&matches).Error
	} else {
		err = db.GetDB().Order("id desc").Where("training_run_id = ?", run).Find(&matches).Error
	}
	if c.DefaultQuery("show_all", "1") == "0" {
		matches = matches[0:99]
	}
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	var networks []db.Network
	if run == "" {
		err = db.GetDB().Order("id").Find(&networks).Error
	} else {
		err = db.GetDB().Order("id").Where("training_run_id=?", run).Find(&networks).Error
	}
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	number := make(map[uint]uint)
	for _, network := range networks {
		number[network.ID] = network.NetworkNumber
	}

	json := []gin.H{}
	for _, match := range matches {
		elo := calcElo(match.Wins, match.Losses, match.Draws)
		elo_error := calcEloError(match.Wins, match.Losses, match.Draws)
		elo_error_str := "Nan"
		if !math.IsNaN(elo_error) {
			elo_error_str = fmt.Sprintf("±%.1f", elo_error)
		}
		table_class := "active"
		if match.Done {
			if match.Passed {
				table_class = "success"
			} else if match.SpecialParams {
				table_class = "warning"
			} else if match.TestOnly {
				table_class = "info"
			} else {
				table_class = "danger"
			}
		}

		passed := "true"
		if !match.Passed {
			passed = "false"
		}
		if match.TestOnly {
			passed = "test"
		}

		json = append(json, gin.H{
			"id":          match.ID,
			"training_id": match.TrainingRunID,
			"current":     number[match.CurrentBestID],
			"candidate":   number[match.CandidateID],
			"score":       fmt.Sprintf("+%d -%d =%d", match.Wins, match.Losses, match.Draws),
			"elo":         fmt.Sprintf("%.1f", elo),
			"error":       elo_error_str,
			"done":        match.Done,
			"table_class": table_class,
			"passed":      passed,
			"created_at":  match.CreatedAt.Format("2006-01-02 15:04:05 -07:00"),
		})
	}

	c.HTML(http.StatusOK, "matches", gin.H{
		"matches": json,
	})
}

func viewMatch(c *gin.Context) {
	match := db.Match{}
	err := db.GetDB().Where("id = ?", c.Param("id")).First(&match).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	games := []db.MatchGame{}
	err = db.GetDB().Where(&db.MatchGame{MatchID: match.ID}).Preload("User").Order("id").Find(&games).Error
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}

	gamesJson := []gin.H{}
	for _, game := range games {
		color := "white"
		if game.Flip {
			color = "black"
		}
		result := "-"
		if game.Done {
			if game.Result == 1 {
				result = "win"
			} else if game.Result == -1 {
				result = "loss"
			} else {
				result = "draw"
			}
		}
		gamesJson = append(gamesJson, gin.H{
			"id":         game.ID,
			"created_at": game.CreatedAt.Format("2006-01-02 15:04:05 -07:00"),
			"result":     result,
			"done":       game.Done,
			"user":       game.User.Username,
			"color":      color,
		})
	}

	c.HTML(http.StatusOK, "match", gin.H{
		"games": gamesJson,
	})
}

func viewTrainingData(c *gin.Context) {
	rows, err := db.GetDB().Raw(`SELECT MAX(id) FROM training_games WHERE compacted = true`).Rows()
	if err != nil {
		log.Println(err)
		c.String(500, "Internal error")
		return
	}
	var id uint
	{
		defer rows.Close()
		for rows.Next() {
			rows.Scan(&id)
			break
		}
	}
	files := []gin.H{}
	game_id := int(id + 1 - 500000)
	if game_id < 0 {
		game_id = 0
	}
	for game_id < int(id) {
		files = append([]gin.H{
			{"url": fmt.Sprintf("https://s3.amazonaws.com/lczero/training/games%d.tar.gz", game_id)},
		}, files...)
		game_id += 10000
	}

	pgnFiles := []gin.H{}
	pgnId := 9000000
	for pgnId < int(id-500000) {
		pgnFiles = append([]gin.H{
			{"url": fmt.Sprintf("https://s3.amazonaws.com/lczero/training/run1/pgn%d.tar.gz", pgnId)},
		}, pgnFiles...)
		pgnId += 100000
	}

	c.HTML(http.StatusOK, "training_data", gin.H{
		"files":     files,
		"pgn_files": pgnFiles,
	})
}

func createTemplates() multitemplate.Render {
	r := multitemplate.New()
	r.AddFromFiles("index", "templates/base.tmpl", "templates/index.tmpl")
	r.AddFromFiles("user", "templates/base.tmpl", "templates/user.tmpl")
	r.AddFromFiles("client", "templates/base.tmpl", "templates/client.tmpl")
	r.AddFromFiles("game", "templates/base.tmpl", "templates/game.tmpl")
	r.AddFromFiles("networks", "templates/base.tmpl", "templates/networks.tmpl")
	r.AddFromFiles("training_runs", "templates/base.tmpl", "templates/training_runs.tmpl")
	r.AddFromFiles("training_run", "templates/base.tmpl", "templates/training_run.tmpl")
	r.AddFromFiles("stats", "templates/base.tmpl", "templates/stats.tmpl")
	r.AddFromFiles("match", "templates/base.tmpl", "templates/match.tmpl")
	r.AddFromFiles("matches", "templates/base.tmpl", "templates/matches.tmpl")
	r.AddFromFiles("training_data", "templates/base.tmpl", "templates/training_data.tmpl")
	r.AddFromFiles("active_users", "templates/base.tmpl", "templates/active_users.tmpl")
	r.AddFromFiles("game_moved", "templates/base.tmpl", "templates/game_moved.tmpl")
	return r
}

func setupRouter() *gin.Engine {
	router := gin.Default()
	router.HTMLRender = createTemplates()
	router.MaxMultipartMemory = 32 << 20 // 32 MiB
	router.Static("/css", "./public/css")
	router.Static("/js", "./public/js")
	router.Static("/images", "./public/images")
	router.Static("/stats", "./netstats")

	router.GET("/", frontPage)
	router.GET("/get_network", getNetwork)
	router.GET("/cached/network/sha/:sha", cachedGetNetwork)
	router.GET("/user/:name", user)
	router.GET("/client/:name/:client_name", client)
	router.GET("/client/:name", client)
	router.GET("/game/:id", game)
	router.GET("/networks/*run", viewNetworks)
	router.GET("/stats", viewStats)
	router.GET("/training_runs", viewTrainingRuns)
	router.GET("/training_run/:run", viewTrainingRun)
	router.GET("/match/:id", viewMatch)
	router.GET("/matches/*run", viewMatches)
	router.GET("/active_users", viewActiveUsers)
	router.GET("/match_game/:id", viewMatchGame)
	router.GET("/training_data", viewTrainingData)
	router.GET("/game_moved", func(c *gin.Context) { c.HTML(http.StatusOK, "game_moved", nil) })
	router.POST("/next_game", nextGame)
	router.POST("/upload_game", uploadGame)
	router.POST("/upload_network", uploadNetwork)
	router.POST("/match_result", matchResult)
	return router
}

func main() {
	db.Init()
	db.SetupDB()
	defer db.Close()

	router := setupRouter()
	router.Run(config.Config.WebServer.Address)
}
