package main

import (
	"errors"
	"fmt"
	"io/ioutil"
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
	log.Print("## checkEIPAndNonEIPUntilStop: Polling source IP and incrementing metric counts for Egress IP or Node IP seen as source IP")
	defer wg.Done()
	var done bool
	start := time.Now()
	var eipCheckFailed bool
	var startupLatencySet bool
	client := getHTTPClient(timeout)

	for !done {
		select {
		case <-stop:
			done = true
		default:
			url := buildDstURL(extHost, extPort)
			res, err := client.Get(url)
			var ipType IPType

			if err != nil {
				log.Printf("Error: Failed to talk to %q: %v", url, err)
			} else {
				if res.StatusCode == http.StatusOK {
					resBody, err := ioutil.ReadAll(res.Body)
					if err != nil {
						log.Printf("Error: %v, while calling ioutil.ReadAll", err)
					} else {
						sourceIP := strings.TrimSpace(string(resBody))
						var valid bool
						valid, ipType = validateIPAddress(sourceIP, egressIPs, hostSubnetStr)
						log.Printf("Source IP: %s, Type: %s, Valid: %v", sourceIP, ipType, valid)
					}
				} else {
					log.Printf("res.StatusCode %d", res.StatusCode)
					err = errors.New(fmt.Sprintf("res.StatusCode %d", res.StatusCode))
				}
				res.Body.Close()
			}

			if err != nil {
				if !eipCheckFailed {
					eipCheckFailed = true
					start = time.Now()
				}
				(*failure).Inc()
			} else {
				switch ipType {
				case IPTypeEgress:
					(*eipTick).Inc()
					if !startupLatencySet {
						(*eipStartUpLatency).Set(time.Now().Sub(start).Seconds())
						log.Printf("Startup Latency: %v seconds", time.Now().Sub(start).Seconds())
						startupLatencySet = true
					} else if eipCheckFailed {
						eipCheckFailed = false
						(*eipRecoveryLatency).Set(time.Now().Sub(start).Seconds())
						log.Printf("Failover/Recovery Latency: %v seconds", time.Now().Sub(start).Seconds())
						start = time.Now()
					}

				case IPTypeNode:
					log.Printf("Node IP detected as source — egress IP not yet active or failed over")
					(*nonEIPTick).Inc()
					if !startupLatencySet {
						(*startupNonEIPTick).Inc()
					} else if !eipCheckFailed {
						eipCheckFailed = true
						start = time.Now()
					}

				case IPTypeInvalid:
					log.Printf("Invalid or unrecognized source IP")
					(*failure).Inc()
				}
			}

			if delayBetweenReq != 0 {
				time.Sleep(time.Duration(delayBetweenReq) * time.Second)
			}
		}
	}
	log.Print("Finished polling source IP")
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
