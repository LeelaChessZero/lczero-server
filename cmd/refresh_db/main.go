package main

import (
	"log"
	"db"

	"github.com/marcsauter/single"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	s := single.New("refresh_db")
	if err := s.CheckLock(); err != nil && err == single.ErrAlreadyRunning {
		log.Fatal("another instance of the app is already running, exiting")
	} else if err != nil {
		// Another error occurred, might be worth handling it as well
		log.Fatalf("failed to acquire exclusive app lock: %v", err)
	}
	defer s.TryUnlock()

	db.Init()
	defer db.Close()

	err := db.GetDB().Exec("REFRESH MATERIALIZED VIEW games_month;").Error
	if err != nil {
		log.Fatal(err)
	}
	err := db.GetDB().Exec("REFRESH MATERIALIZED VIEW games_all;").Error
	if err != nil {
		log.Fatal(err)
	}
}
