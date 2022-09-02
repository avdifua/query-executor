package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var input struct {
	username    string
	password    string
	dbaUsername string
	dbaPassword string
	hostsFile   string
	queriesFile string
}

type SessionWork struct {
	replicationType   string
	queryResult       string
	queryMasterStatus string
	sessionResult     int
}

var readfile struct {
	hosts   []string
	queries []string
}

func credentials() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	input.username, _ = reader.ReadString('\n')
	input.username = strings.TrimSuffix(input.username, "\n")
	
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}
	input.password = string(bytePassword)
	
	fmt.Print("\nEnter DBA username: ")
	input.dbaUsername, _ = reader.ReadString('\n')
	input.dbaUsername = strings.TrimSuffix(input.username, "\n")
	
	fmt.Print("Enter DBA password: \n")
	byteDBAPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}
	input.dbaPassword = string(byteDBAPassword)

	validate(map[string]string{"username": input.username, "password": input.password, "dbaPassword": input.dbaPassword})

}

func validate(args map[string]string) {
	for k, v := range args {
		if len(v) == 0 {
			fmt.Printf("The %s is required.", k)
			os.Exit(2)
		}
	}
}

func getArguments() {
	flag.StringVar(&input.hostsFile, "hosts", input.hostsFile, "Path to file with hosts")
	flag.StringVar(&input.queriesFile, "queries", input.queriesFile, "Path to file with queries")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "This script requires 2 arguments. Paths to files with hosts and queries.\nExample: -hosts /home/user/hosts.txt -queries /home/user/queries.txt\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	validate(map[string]string{"Path to file with queries": input.queriesFile, "Path to file with hosts": input.hostsFile})
}

func readFiles() {
	listOfFiles := []string{input.hostsFile, input.queriesFile}
	wg := new(sync.WaitGroup)

	for _, file := range listOfFiles {
		wg.Add(1)
		go func(file string) {
			dataFromFile, err := os.Open(file)
			if err != nil {
				log.Fatal(err)
			}
			defer func(dataFromFile *os.File) {
				err := dataFromFile.Close()
				if err != nil {
					log.Fatal(err)
				}
			}(dataFromFile)
			scanner := bufio.NewScanner(dataFromFile)
			for scanner.Scan() {
				if len(scanner.Text()) > 0 {
					if strings.Contains(file, "hosts") {
						readfile.hosts = append(readfile.hosts, scanner.Text())
					} else {
						readfile.queries = append(readfile.queries, scanner.Text())
					}
				}
			}
			wg.Done()
		}(file)
	}
	wg.Wait()
}

func SshInteractive(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	answers = make([]string, len(questions))
	for n, _ := range questions {
		answers[n] = input.password
	}
	return answers, nil
}

func SshSession(user, dbaUser, host, password, query string, newV *SessionWork) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(SshInteractive),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{"diffie-hellman-group-exchange-sha256",
				"curve25519-sha256@libssh.org ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384 ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group1-sha1",
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
				"arcfour256",
				"arcfour128",
				"arcfour",
			},
		},
	}

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		fmt.Println("Failed to dial: "+err.Error(), "\nProbably username or password is not valid!")
		os.Exit(2)
	}

	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run(fmt.Sprintf("export TMP_DBA_PASS='%s' && mysql -u %s -p$TMP_DBA_PASS -e \"%s\"", password, dbaUser, query)); err != nil {

		if newV.sessionResult == 0 {
			fmt.Printf("\nUser %s can't login, trying login to %s as %s\n", input.dbaUsername, strings.TrimSuffix(host, ":22"), input.username)
		} else if query == "show slave status \\G" {
			fmt.Printf("\nCan't log in MySQL with provided credentials on host %s\n", strings.TrimSuffix(host, ":22"))
		} else {
			fmt.Println("\nYour query returned an error. Check syntax query, please.")
		}
		newV.sessionResult = 1

	} else {
		if newV.replicationType == "master-replica" {
			newV.queryResult = b.String()
		}

		if len(newV.replicationType) == 0 {
			if len(b.String()) == 0 {
				newV.replicationType = "master-replica"
			} else {
				newV.replicationType = "master-master"
				for _, v := range strings.Split(b.String(), "\n") {
					if strings.Contains(v, "Master_Host:") {
						fmt.Printf("\nProbably host %s is a replica or master-master replication. ", strings.TrimSuffix(host, ":22"))
						fmt.Printf("\nPrimary: " + strings.Split(strings.TrimSpace(v), " ")[1] + " Replica: " + strings.TrimSuffix(host, ":22"))
						break
					}
				}
			}
		}
	}
}

func RunQuery(query string, host string, newV *SessionWork) {
	if newV.sessionResult == 0 {
		SshSession(input.username, input.dbaUsername, host, input.dbaPassword, query, newV)
	}
	if newV.sessionResult != 0 {
		SshSession(input.username, input.username, host, input.password, query, newV)
	}

}

func connectViaSsh() {

	wg := new(sync.WaitGroup)
	wg.Add(len(readfile.hosts))

	for _, host := range readfile.hosts {
		go func(host string, wg *sync.WaitGroup) {

			newV := new(SessionWork)
			newV.queryMasterStatus = "show slave status \\G"
			RunQuery(newV.queryMasterStatus, host+":22", newV)

			if newV.replicationType == "master-replica" {
				wg1 := new(sync.WaitGroup)
				for _, q := range readfile.queries {
					wg1.Add(1)
					go func(q string) {

						RunQuery(q, host+":22", newV)

						if len(newV.queryResult) == 0 {
							fmt.Printf("\nQuery \"%s\" executed on host %s but returned an empty set!", q, host)
						} else {
							fmt.Printf("\nQuery \"%s\" executed on host %s and returned:\n%s", q, host, newV.queryResult)
						}
						wg1.Done()
					}(q)
				}
				wg1.Wait()
			} else {
				fmt.Printf("\nQuery not executed on %s\n", host)
			}
			wg.Done()
		}(host, wg)
	}
	wg.Wait()
}

func main() {
	getArguments()
	credentials()
	readFiles()
	connectViaSsh()
}
