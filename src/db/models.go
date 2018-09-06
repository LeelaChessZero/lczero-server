package db

import (
	"time"

	"github.com/jinzhu/gorm"
)

type User struct {
	gorm.Model

	Username string
	Password string
	AssignedTrainingRunID uint
}

type TrainingRun struct {
	gorm.Model

	BestNetwork   Network
	BestNetworkID uint
	Matches       []Match

	Description     string
	TrainParameters string
	Active          bool
	LastNetwork     uint
	LastGame        uint
}

type Network struct {
	ID        uint `gorm:"primary_key"`
	CreatedAt time.Time

	TrainingRunID uint
	// Scoped to training run
	NetworkNumber uint

	Sha  string
	Path string

	Layers  int
	Filters int

	// Cached here, as expensive to do COUNT(*) on Postgresql
	GamesPlayed int

	Elo float64
}

type Match struct {
	gorm.Model

	TrainingRunID uint
	Parameters    string

	Candidate     Network
	CandidateID   uint
	CurrentBest   Network
	CurrentBestID uint

	GamesCreated int

	Wins   int
	Losses int
	Draws  int

	GameCap int
	Done    bool
	Passed  bool

	// If true, this is not a promotion match
	TestOnly bool
}

type MatchGame struct {
	ID        uint64 `gorm:"primary_key"`
	CreatedAt time.Time

	User    User
	UserID  uint
	Match   Match
	MatchID uint

	Version uint
	Pgn     string
	Result  int
	Done    bool
	Flip    bool

	EngineVersion string
}

type TrainingGame struct {
	ID        uint64    `gorm:"primary_key"`
	CreatedAt time.Time `gorm:"index"`

	User          User
	UserID        uint `gorm:"index"`
	TrainingRun   TrainingRun
	TrainingRunID uint
	Network       Network
	NetworkID     uint `gorm:"index"`

	// Scoped to training run.
	GameNumber uint

	Version   uint
	Path      string
	Compacted bool

	EngineVersion string

	ResignFPThreshold float64
}

type ServerData struct {
	gorm.Model

	TrainingPgnUploaded int
}
