package main

import (
	"bufio"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	"net"
	"os"
	"os/exec"
	"regexp"
)

var log = logging.MustGetLogger("enumerate")
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

func initRecords(db *sql.DB) {
	statement := `
create table routes (id integer not null primary key, route text, asn text, owner text);
create table records (id integer not null primary key, name text, addr text, route_id integer not null, foreign key (route_id) references routes(route_id));
delete from routes;
delete from records;
`
	_, err := db.Exec(statement)
	if err != nil {
		log.Fatal(err)
	}
}

func ingest(db *sql.DB, hostListFilename string) {
	var knownRoutes []*net.IPNet
	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err := tx.Prepare("insert into records(id, name, addr, route_id) values(?, ?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	netStmt, err := tx.Prepare("insert into routes(id, route, owner, asn) values(?, ?, ?, ?)")
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
		ip := getFirstIp(name)
		foundNet := false
		netNumber := 0
		for j, subnet := range knownRoutes {
			if subnet.Contains(net.ParseIP(ip)) {
				foundNet = true
				netNumber = j
			}
		}
		if foundNet != true {
			route, asn, netName := getWhois(ip)
			_, routeNet, err := net.ParseCIDR(route)
			if err != nil {
				log.Fatal("Invalid CIDR")
			}
			netNumber = len(knownRoutes)
			_, err = netStmt.Exec(netNumber, route, asn, netName)
			knownRoutes = append(knownRoutes, routeNet)
		}
		_, err = stmt.Exec(i, name, ip, netNumber)
		if err != nil {
			log.Fatal(err)
		}
		i++
	}
	tx.Commit()
}

func getFirstIp(name string) string {
	ips, err := net.LookupIP(name)
	if err == nil {
		ip := ips[0].String()
		log.Debugf("Got %s for %s", ip, name)
		return ip
	} else {
		log.Infof("No record for %s: %v", name, err)
		return ""
	}
}

func getWhois(ip string) (string, string, string) {
	var route string
	var owner string
	var asn string
	routeRE := regexp.MustCompile(`(?m:^route: +(.+)$)`)
	asnRE := regexp.MustCompile(`(?m:^origin: +(.+)$)`)
	ownerRE := regexp.MustCompile(`(?m:^as-name: +(.+)$)`)
	path, err := exec.LookPath("whois")
	if err != nil {
		log.Fatal("Must have `whois` binary in $PATH")
	}
	if cmdOut, err := exec.Command(path, []string{"-m", ip}...).Output(); err != nil {
		log.Errorf("Could not retrieve whois report for %s", ip)
		return "", "", ""
	} else {
		matches := routeRE.FindAllStringSubmatch(string(cmdOut), -1)
		if len(matches) == 0 {
			log.Debugf("Could not match route field")
			route = ""
		} else {
			route = matches[0][1]
		}
		matches = asnRE.FindAllStringSubmatch(string(cmdOut), -1)
		if len(matches) == 0 {
			log.Debugf("Could not match asn field")
			asn = ""
		} else {
			asn = matches[0][1]
		}
		if cmdOut, err = exec.Command(path, []string{"-m", asn}...).Output(); err != nil {
			log.Errorf("Could not retrieve whois report for %s", ip)
			owner = ""
		} else {
			matches = ownerRE.FindAllStringSubmatch(string(cmdOut), -1)
			if len(matches) == 0 {
				log.Debugf("Could not match as-name field")
				owner = ""
			} else {
				owner = matches[0][1]
			}
		}
		log.Infof("Got ASN:%s Route:%s Owner:%s for ip %s", asn, route, owner, ip)
		return route, owner, asn
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
