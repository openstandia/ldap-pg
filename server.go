package main

import (
	"crypto/tls"
	_ "database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/comail/colog"
	"github.com/jsimonetti/pwscheme/ssha512"
	"net/http"
	_ "net/http/pprof"
	//"github.com/hashicorp/logutils"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	ldap "github.com/openstandia/ldapserver"
)

var (
	db        *sqlx.DB
	schemaMap SchemaMap
	mapper    *Mapper
	rootDN    *DN
)

type ServerConfig struct {
	DBHostName        string
	DBPort            int
	DBName            string
	DBUser            string
	DBPassword        string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	Suffix            string
	RootDN            string
	RootPW            string
	PassThroughConfig *PassThroughConfig
	BindAddress       string
	LogLevel          string
	PProfServer       string
	GoMaxProcs        int
}

type Server struct {
	config     *ServerConfig
	rootDN     *DN
	internal   *ldap.Server
	suffixNorm []string
}

func NewServer(c *ServerConfig) *Server {
	hashedRootPW, err := ssha512.Generate(c.RootPW, 20)
	if err != nil {
		log.Fatalf("Initialize rootPW error: %+v", err)
	}
	c.RootPW = hashedRootPW

	s := strings.Split(c.Suffix, ",")
	sn := make([]string, len(s))
	for i := 0; i < len(s); i++ {
		sn[i] = strings.TrimSpace(strings.ToLower(s[i]))
	}

	return &Server{
		config:     c,
		suffixNorm: sn,
	}
}

func (s *Server) Start() {
	// Init logging
	cl := colog.NewCoLog(os.Stdout, "worker ", log.LstdFlags)

	level := strings.ToUpper(s.config.LogLevel)
	if level == "ERROR" {
		cl.SetMinLevel(colog.LError)
		colog.SetMinLevel(colog.LError)
	} else if level == "WARN" {
		cl.SetMinLevel(colog.LWarning)
		colog.SetMinLevel(colog.LWarning)
	} else if level == "INFO" {
		cl.SetMinLevel(colog.LInfo)
		colog.SetMinLevel(colog.LInfo)
	} else if level == "DEBUG" {
		cl.SetMinLevel(colog.LDebug)
		colog.SetMinLevel(colog.LDebug)
	}
	cl.SetDefaultLevel(colog.LDebug)
	colog.SetDefaultLevel(colog.LDebug)
	cl.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lshortfile,
	})
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lshortfile,
	})
	colog.Register()

	if _, ok := ldap.Logger.(*log.Logger); ok {
		ldap.Logger = cl.NewLogger()
	}

	// Launch pprof
	if s.config.PProfServer != "" {
		go func() {
			log.Println(http.ListenAndServe(s.config.PProfServer, nil))
		}()
	}

	// Init GOMAXPROCS
	if s.config.GoMaxProcs > 0 {
		log.Printf("info: Setup GOMAXPROCS: %d. NumCPU: %d\n", s.config.GoMaxProcs, runtime.NumCPU())
		runtime.GOMAXPROCS(s.config.GoMaxProcs)
	} else {
		log.Printf("info: Setup GOMAXPROCS with NumCPU: %d\n", runtime.NumCPU())
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	var err error

	// Init DB connection
	db, err = sqlx.Connect("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable", s.config.DBHostName, s.config.DBPort, s.config.DBUser, s.config.DBName, s.config.DBPassword))
	if err != nil {
		log.Fatalf("fatal: Connect error. host=%s, port=%d, user=%s, dbname=%s, error=%s", s.config.DBHostName, s.config.DBPort, s.config.DBUser, s.config.DBName, err)
	}
	db.SetMaxOpenConns(s.config.DBMaxOpenConns)
	db.SetMaxIdleConns(s.config.DBMaxIdleConns)
	// db.SetConnMaxLifetime(time.Hour)

	// Init prepared statement
	err = initStmt(db)
	if err != nil {
		log.Fatalf("fatal: Prepare statement error:  %+v", err)
	}

	// Init schema map
	schemaMap = InitSchemaMap()
	if s, ok := schemaMap.Get("entryUUID"); ok {
		s.UseIndependentColumn("uuid")
	}
	if s, ok := schemaMap.Get("createTimestamp"); ok {
		s.UseIndependentColumn("created")
	}
	if s, ok := schemaMap.Get("modifyTimestamp"); ok {
		s.UseIndependentColumn("updated")
	}

	// Init mapper
	mapper = NewMapper(schemaMap)

	// Init rootDN
	s.rootDN, err = normalizeDN(s.config.RootDN)
	if err != nil {
		log.Fatalf("fatal: Invalid root-dn format: %s, err: %s", s.config.RootDN, err)
	}

	//Create a new LDAP Server
	server := ldap.NewServer()
	s.internal = server

	//Create routes bindings
	routes := ldap.NewRouteMux()
	routes.NotFound(handleNotFound)
	routes.Abandon(handleAbandon)
	routes.Bind(NewHandler(s, handleBind))
	routes.Compare(handleCompare)
	routes.Add(NewHandler(s, handleAdd))
	routes.Delete(handleDelete)
	routes.Modify(handleModify)
	routes.ModifyDN(handleModifyDN)

	routes.Extended(handleStartTLS).
		RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")

	routes.Extended(handleWhoAmI).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")

	routes.Extended(handleExtended).Label("Ext - Generic")

	routes.Search(NewHandler(s, handleSearchDSE)).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")

	routes.Search(handleSearchSubschema).
		BaseDn("cn=Subschema").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - Subschema")

	routes.Search(handleSearch).Label("Search - Generic")

	//Attach routes to server
	server.Handle(routes)

	// Optional config
	server.MaxRequestSize = 5 * 1024 * 1024 // 5MB

	log.Printf("info: Starting ldap-pg on %s", *bindAddress)

	// listen and serve
	go server.ListenAndServe(*bindAddress)

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

func (s *Server) Stop() {
	s.internal.Stop()
}

func (s *Server) SuffixNorm() []string {
	return s.suffixNorm
}

func NewHandler(s *Server, handler func(s *Server, w ldap.ResponseWriter, r *ldap.Message)) func(w ldap.ResponseWriter, r *ldap.Message) {
	return func(w ldap.ResponseWriter, r *ldap.Message) {
		handler(s, w, r)
	}
}

func handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	switch r.ProtocolOpType() {
	case ldap.ApplicationBindRequest:
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")

		w.Write(res)

	default:
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
	var req = m.GetAbandonRequest()
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
		log.Printf("info: Abandon signal sent to request processor [messageID=%d]", int(req))
	}
}

func handleExtended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	log.Printf("info: Extended request received, name=%s", r.RequestName())
	log.Printf("info: Extended request received, value=%x", r.RequestValue())
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// localhostCert is a PEM-encoded TLS cert with SAN DNS names
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBOTCB5qADAgECAgEAMAsGCSqGSIb3DQEBBTAAMB4XDTcwMDEwMTAwMDAwMFoX
DTQ5MTIzMTIzNTk1OVowADBaMAsGCSqGSIb3DQEBAQNLADBIAkEAsuA5mAFMj6Q7
qoBzcvKzIq4kzuT5epSp2AkcQfyBHm7K13Ws7u+0b5Vb9gqTf5cAiIKcrtrXVqkL
8i1UQF6AzwIDAQABo08wTTAOBgNVHQ8BAf8EBAMCACQwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDAbBgNVHREEFDASggkxMjcuMC4wLjGCBVs6OjFdMAsG
CSqGSIb3DQEBBQNBAJH30zjLWRztrWpOCgJL8RQWLaKzhK79pVhAx6q/3NrF16C7
+l1BRZstTwIGdoGId8BRpErK1TXkniFb95ZMynM=
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBALLgOZgBTI+kO6qAc3LysyKuJM7k+XqUqdgJHEH8gR5uytd1rO7v
tG+VW/YKk3+XAIiCnK7a11apC/ItVEBegM8CAwEAAQJBAI5sxq7naeR9ahyqRkJi
SIv2iMxLuPEHaezf5CYOPWjSjBPyVhyRevkhtqEjF/WkgL7C2nWpYHsUcBDBQVF0
3KECIQDtEGB2ulnkZAahl3WuJziXGLB+p8Wgx7wzSM6bHu1c6QIhAMEp++CaS+SJ
/TrU0zwY/fW4SvQeb49BPZUF3oqR8Xz3AiEA1rAJHBzBgdOQKdE3ksMUPcnvNJSN
poCcELmz2clVXtkCIQCLytuLV38XHToTipR4yMl6O+6arzAjZ56uq7m7ZRV0TwIh
AM65XAOw8Dsg9Kq78aYXiOEDc5DL0sbFUu/SlmRcCg93
-----END RSA PRIVATE KEY-----
`)

// getTLSconfig returns a tls configuration used
// to build a TLSlistener for TLS or StartTLS
func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}, nil
}

func handleStartTLS(w ldap.ResponseWriter, m *ldap.Message) {
	tlsconfig, _ := getTLSconfig()
	tlsConn := tls.Server(m.Client.GetConn(), tlsconfig)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("warn: StartTLS Handshake error %v", err)
		res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
		res.SetResultCode(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	m.Client.SetConn(tlsConn)
	log.Println("StartTLS OK")
}

func (s *Server) GetSuffix() string {
	return s.config.Suffix
}

func (s *Server) GetRootDN() *DN {
	return s.rootDN
}

func (s *Server) GetRootPW() string {
	return s.config.RootPW
}
