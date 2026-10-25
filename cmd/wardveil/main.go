package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GoreeCloud/wardveil/internal/httpapi"
	"github.com/GoreeCloud/wardveil/internal/store"
)

func run() error {
	listen := os.Getenv("WARDVEIL_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8787"
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("prototype only allows explicit loopback IP listener; terminate TLS at an approved boundary in future")
	}
	dataDir := os.Getenv("WARDVEIL_DATA_DIR")
	if dataDir == "" {
		dataDir = "./var"
	}
	data, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	defer data.Close()
	api, err := httpapi.New(data, os.Getenv("WARDVEIL_INGEST_TOKEN"), os.Getenv("WARDVEIL_READ_TOKEN"))
	if err != nil {
		return err
	}
	server := &http.Server{Addr: listen, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	go func() {
		<-stopped
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	log.Printf("Wardveil development event service listening on loopback %s", listen)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
