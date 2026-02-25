package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	serverEnvKey              = "EXT_SERVER_HOST"
	portEnvKey                = "EXT_SERVER_PORT"
	egressIPsEnvKey           = "EGRESS_IPS"
	hostSubnetEnvKey          = "HOST_SUBNET"
	delayBetweenRequestEnvKey = "DELAY_BETWEEN_REQ_SEC"
	reqTimeoutEnvKey          = "REQ_TIMEOUT_SEC"
	envKeyErrMsg              = "define env key %q"
	defaultDelayBetweenReqSec = 1
	defaultRequestTimeoutSec  = 1
)

// IPType represents whether the source IP is an Egress IP, a Node IP, or neither.
type IPType int

const (
	IPTypeInvalid IPType = iota
	IPTypeEgress
	IPTypeNode
)

func (t IPType) String() string {
	switch t {
	case IPTypeEgress:
		return "EgressIP"
	case IPTypeNode:
		return "NodeIP"
	default:
		return "Invalid"
	}
}

func main() {
	wg := &sync.WaitGroup{}
	stop := registerSignalHandler()
	extHost, extPort, egressIPsStr, hostSubnetStr, delayBetweenReq, timeout := processEnvVars()
	egressIPs := make(map[string]struct{})
	if egressIPsStr != "" {
		egressIPs = buildEIPMap(egressIPsStr)
	}
	startupNonEIPTick, eipStartUpLatency, eipRecoveryLatency, eipTick, nonEIPTick, failure := buildAndRegisterMetrics(delayBetweenReq)
	wg.Add(2)
	startMetricsServer(stop, wg)
	wg.Add(1)
	go checkEIPAndNonEIPUntilStop(stop, wg, egressIPs, hostSubnetStr, extHost, extPort, eipStartUpLatency, eipRecoveryLatency, startupNonEIPTick, eipTick, nonEIPTick, failure, delayBetweenReq, timeout)
	wg.Wait()
}

// validateIPAddress checks whether ipAddr is a valid egress IP or a node IP (within the host subnet).
// It returns:
//   - valid bool   : true if the IP is either an egress IP or a node IP
//   - ipType IPType: IPTypeEgress, IPTypeNode, or IPTypeInvalid
func validateIPAddress(ipAddr string, egressIPs map[string]struct{}, subnet string) (bool, IPType) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		log.Printf("Error: IP Address %q could not be parsed", ipAddr)
		return false, IPTypeInvalid
	}

	// Check against the known egress IPs first.
	if len(egressIPs) > 0 {
		if _, ok := egressIPs[ipAddr]; ok {
			return true, IPTypeEgress
		}
	}

	// If a host subnet is provided, check whether the IP falls within it (node IP).
	if subnet != "" {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			log.Printf("Error: Failed to parse subnet %q: %v", subnet, err)
			return false, IPTypeInvalid
		}
		if ipNet.Contains(ip) {
			return true, IPTypeNode
		}
	}

	return false, IPTypeInvalid
}

func checkEIPAndNonEIPUntilStop(stop <-chan struct{}, wg *sync.WaitGroup, egressIPs map[string]struct{}, hostSubnetStr string, extHost, extPort string,
	eipStartUpLatency, eipRecoveryLatency *prometheus.Gauge, startupNonEIPTick, eipTick, nonEIPTick *prometheus.Gauge, failure *prometheus.Gauge, delayBetweenReq, timeout int) {
	log.Print("## checkEIPAndNonEIPUntilStop: Polling source IP and incrementing metric counts")
	defer wg.Done()

	client := getHTTPClient(timeout)
	startupBegin := time.Now()
	var startupDone bool      // flips to true once the first egress IP is seen
	var failedSince time.Time // zero value means egress IP is healthy; non-zero marks start of failure window

	for {
		select {
		case <-stop:
			log.Print("Finished polling source IP")
			return
		default:
		}

		ipType, err := fetchSourceIPType(client, extHost, extPort, egressIPs, hostSubnetStr)
		log.Printf("startupDone=%v failedSince=%v ipType=%s err=%v", startupDone, failedSince, ipType, err)

		// Connection error or non-200: always a failure.
		// Only begin tracking recovery time once startup has completed.
		if err != nil {
			(*failure).Inc()
			if startupDone && failedSince.IsZero() {
				failedSince = time.Now()
			}
		} else {
			switch ipType {
			case IPTypeEgress:
				// Record startup latency exactly once on the first egress IP seen.
				if !startupDone {
					(*eipStartUpLatency).Set(time.Since(startupBegin).Seconds())
					log.Printf("Startup latency: %v seconds", time.Since(startupBegin).Seconds())
					startupDone = true
				}
				(*eipTick).Inc()
				// If we were in a failure window, record recovery latency and close the window.
				if !failedSince.IsZero() {
					(*eipRecoveryLatency).Set(time.Since(failedSince).Seconds())
					log.Printf("Recovery latency: %v seconds", time.Since(failedSince).Seconds())
					failedSince = time.Time{}
				}

			case IPTypeNode:
				// Before startup: count toward startup non-EIP metric (mutually exclusive with nonEIPTick).
				// After startup: count toward steady-state non-EIP metric and open a failure window.
				if !startupDone {
					(*startupNonEIPTick).Inc()
				} else {
					(*nonEIPTick).Inc()
					if failedSince.IsZero() {
						failedSince = time.Now()
					}
				}

			case IPTypeInvalid:
				// Unrecognized IP — treat same as a connection failure.
				(*failure).Inc()
				if startupDone && failedSince.IsZero() {
					failedSince = time.Now()
				}
			}
		}

		if delayBetweenReq != 0 {
			time.Sleep(time.Duration(delayBetweenReq) * time.Second)
		}
	}
}

// fetchSourceIPType makes a single HTTP request and returns the IPType of the source IP.
// Returns IPTypeInvalid with a non-nil error on connection failure, non-200 response, or unreadable body.
func fetchSourceIPType(client http.Client, extHost, extPort string, egressIPs map[string]struct{}, hostSubnetStr string) (IPType, error) {
	url := buildDstURL(extHost, extPort)
	res, err := client.Get(url)
	if err != nil {
		log.Printf("Error: Failed to talk to %q: %v", url, err)
		return IPTypeInvalid, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", res.StatusCode)
		log.Printf("Error: %v", err)
		return IPTypeInvalid, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Error: %v, while reading response body", err)
		return IPTypeInvalid, err
	}

	sourceIP := strings.TrimSpace(string(resBody))
	_, ipType := validateIPAddress(sourceIP, egressIPs, hostSubnetStr)
	log.Printf("Source IP: %s, Type: %s", sourceIP, ipType)
	return ipType, nil
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func buildDstURL(host, port string) string {
	return fmt.Sprintf("http://%s:%s", host, port)
}

func getHTTPClient(timeout int) http.Client {
	return http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
}

func buildEIPMap(egressIPsStr string) map[string]struct{} {
	egressIPs := strings.Split(egressIPsStr, ",")
	egressIPMap := make(map[string]struct{})
	for _, egressIP := range egressIPs {
		if ip := net.ParseIP(egressIP); ip == nil {
			panic(fmt.Sprintf("invalid egress IPs - comma separated list allowed: %q", egressIPsStr))
		}
		egressIPMap[egressIP] = struct{}{}
	}
	return egressIPMap
}

func processEnvVars() (string, string, string, string, int, int) {
	var err error
	extHost := os.Getenv(serverEnvKey)
	if extHost == "" {
		panic(fmt.Sprintf(envKeyErrMsg, serverEnvKey))
	}
	extPort := os.Getenv(portEnvKey)
	if extPort == "" {
		panic(fmt.Sprintf(envKeyErrMsg, portEnvKey))
	}
	hostSubnetStr := ""
	egressIPsStr := os.Getenv(egressIPsEnvKey)
	if egressIPsStr == "" {
		hostSubnetStr = os.Getenv(hostSubnetEnvKey)
		if hostSubnetStr == "" {
			panic(fmt.Sprintf(envKeyErrMsg, egressIPsEnvKey))
		}
	}

	delayBetweenReq := defaultDelayBetweenReqSec
	delayBetweenRequestStr := os.Getenv(delayBetweenRequestEnvKey)
	if delayBetweenRequestStr != "" {
		delayBetweenReq, err = strconv.Atoi(delayBetweenRequestStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse delay between requests: %v", err))
		}
	}
	requestTimeout := defaultRequestTimeoutSec
	reqTimeoutStr := os.Getenv(reqTimeoutEnvKey)
	if reqTimeoutStr != "" {
		requestTimeout, err = strconv.Atoi(reqTimeoutStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse request timeout %q: %v", reqTimeoutStr, err))
		}
	}
	return extHost, extPort, egressIPsStr, hostSubnetStr, delayBetweenReq, requestTimeout
}

func registerSignalHandler() chan struct{} {
	stop := make(chan struct{})
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		close(stop)
	}()
	return stop
}

func startMetricsServer(stop <-chan struct{}, wg *sync.WaitGroup) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{Addr: ":8080", Handler: mux}
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		<-stop
		if err := server.Close(); err != nil {
			panic(err.Error())
		}
	}()
}

func buildAndRegisterMetrics(delayBetweenReq int) (*prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge) {
	var startupNonEIPTick = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "startup_non_eip_total",
		Help:      fmt.Sprintf("during startup, increments every time EgressIP not seen as source IP - increments every %d seconds if seen", delayBetweenReq),
	})

	var eipStartUpLatency = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "eip_startup_latency_total",
		Help: fmt.Sprintf("time it takes in seconds for a connection to have a source IP of EgressIP at startup"+
			" with polling interval of %d seconds", delayBetweenReq),
	})
	var eipRecoveryLatency = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "eip_recovery_latency",
		Help: fmt.Sprintf("time it takes in seconds for an Egress IP connection to recover from failure"+
			" with polling interval of %d seconds", delayBetweenReq),
	})

	var eipTick = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "eip_total",
		Help:      fmt.Sprintf("increments every time EgressIP seen as source IP - increments every %d seconds if seen", delayBetweenReq),
	})

	var nonEIPTick = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "non_eip_total",
		Help:      fmt.Sprintf("increments every time EgressIP not seen as source IP (Node IP seen instead) - increments every %d seconds if seen", delayBetweenReq),
	})

	var failure = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "failure_total",
		Help:      fmt.Sprintf("increments every time there is a connection failure or unrecognized IP - increments every %d seconds if seen", delayBetweenReq),
	})

	prometheus.MustRegister(startupNonEIPTick)
	prometheus.MustRegister(eipStartUpLatency)
	prometheus.MustRegister(eipRecoveryLatency)
	prometheus.MustRegister(eipTick)
	prometheus.MustRegister(nonEIPTick)
	prometheus.MustRegister(failure)
	return &startupNonEIPTick, &eipStartUpLatency, &eipRecoveryLatency, &eipTick, &nonEIPTick, &failure
}
