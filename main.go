package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func run() error {
	configPath := flag.String("config", "", "JSON configuration file (optional; defaults discard on loopback)")
	stateDir := flag.String("state-dir", "./state", "metadata journal and dashboard state directory")
	check := flag.Bool("check", false, "validate configuration and exit without listeners")
	flag.Parse()
	c := DefaultConfig()
	if *configPath != "" {
		var e error
		c, e = LoadConfig(*configPath)
		if e != nil {
			return e
		}
	}
	if *check {
		if e := ValidateConfig(c); e != nil {
			return e
		}
		fmt.Println("configuration valid")
		return nil
	}
	store, e := NewStore(*stateDir)
	if e != nil {
		return fmt.Errorf("cannot initialize metadata store")
	}
	if saved := store.SavedConfig(); saved != nil {
		saved.SMTPListen = c.SMTPListen
		saved.AdminListen = c.AdminListen
		saved.Domain = c.Domain
		saved.Limits = c.Limits
		c = *saved
	}
	app, e := NewApp(c, func(e Event) {
		if err := store.RecordEvent(e); err != nil {
			log.Print("metadata journal write failed")
		}
	})
	if e != nil {
		return e
	}
	smtpListener, e := net.Listen("tcp", c.SMTPListen)
	if e != nil {
		return fmt.Errorf("cannot bind SMTP listener")
	}
	defer smtpListener.Close()
	adminListener, e := net.Listen("tcp", c.AdminListen)
	if e != nil {
		return fmt.Errorf("cannot bind admin listener")
	}
	defer adminListener.Close()
	errors := make(chan error, 2)
	go func() { errors <- app.ServeSMTP(smtpListener) }()
	server := &http.Server{Handler: NewDashboard(app, store), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() { errors <- server.Serve(adminListener) }()
	log.Printf("pabal ready: mode=%s smtp=%s admin=%s; synchronous forwarding has no delivery queue", c.Mode, c.SMTPListen, c.AdminListen)
	return <-errors
}
func main() {
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
