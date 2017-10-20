package main

import (
	"bufio"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	"net"
	"os"
)

var log = logging.MustGetLogger("enumerate")
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

func initRecords(db *sql.DB) {
	statement := `
create table records (id integer not null primary key, name text, addr text);
delete from records;
`
	_, err := db.Exec(statement)
	if err != nil {
		log.Fatal(err)
	}
}

func ingest(db *sql.DB, hostListFilename string) {
	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err := tx.Prepare("insert into records(id, name, addr) values(?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	fh, err := os.Open(hostListFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)
	i := 0
	for scanner.Scan() {
		name := scanner.Text()
		fmt.Println("Ingesting", name)
		_, err = stmt.Exec(i, name, getFirstIp(name))
		i++
	}
	tx.Commit()
}

func getFirstIp(name string) string {
	ips, err := net.LookupIP(name)
	if err == nil {
		ip := ips[0].String()
		log.Debugf("Recording %s for %s", ip, name)
		return ip
	} else {
		log.Debugf("No record for %s: %v", name, err)
		return ""
	}
}

func main() {
	fmt.Println("Enumerate innit")

	logBackend := logging.NewLogBackend(os.Stderr, "", 0)
	logBackendFormatter := logging.NewBackendFormatter(logBackend, format)
	leveledLogBackend := logging.AddModuleLevel(logBackend)
	leveledLogBackend.SetLevel(logging.DEBUG, "")
	logging.SetBackend(leveledLogBackend, logBackendFormatter)

	dbFile := "./enumerate.db"
	os.Remove(dbFile)
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initRecords(db)
	ingest(db, "./enumerate.txt")
	os.Exit(0)
}
