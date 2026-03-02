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
	delayBetweenRequestEnvKey = "DELAY_BETWEEN_REQ_SEC"
	reqTimeoutEnvKey          = "REQ_TIMEOUT_SEC"
	envKeyErrMsg              = "define env key %q"
	defaultDelayBetweenReqSec = 1
	defaultRequestTimeoutSec  = 1
)

func main() {
	wg := &sync.WaitGroup{}
	stop := registerSignalHandler()
	extHost, extPort, egressIPsStr, delayBetweenReq, timeout := processEnvVars()
	egressIPs := buildEIPMap(egressIPsStr)
	eipStartUpLatency, eipRecoveryLatency, failure, randomFailure, failoverWindowFailure := buildAndRegisterMetrics(delayBetweenReq)
	wg.Add(2)
	startMetricsServer(stop, wg)
	wg.Add(1)
	go checkEIPUntilStop(stop, wg, egressIPs, extHost, extPort, eipStartUpLatency, eipRecoveryLatency, failure, randomFailure, failoverWindowFailure, delayBetweenReq, timeout)
	wg.Wait()
}

// parseAndCheckEgressIP parses the raw IP string from the response body.
// Returns:
//   - validIP bool  : false if the string is not a parseable IP at all (treat as request failure)
//   - isEgress bool : true if the IP is one of the known egress IPs
func parseAndCheckEgressIP(ipAddr string, egressIPs map[string]struct{}) (validIP bool, isEgress bool) {
	if net.ParseIP(ipAddr) == nil {
		log.Printf("Error: IP Address %q could not be parsed", ipAddr)
		return false, false
	}
	_, isEgress = egressIPs[ipAddr]
	return true, isEgress
}

func checkEIPUntilStop(stop <-chan struct{}, wg *sync.WaitGroup, egressIPs map[string]struct{}, extHost, extPort string,
	eipStartUpLatency, eipRecoveryLatency *prometheus.Gauge,
	failure, randomFailure, failoverWindowFailure *prometheus.Gauge,
	delayBetweenReq, timeout int) {
	log.Print("## checkEIPUntilStop: Polling source IP and tracking EgressIP health")
	defer wg.Done()
	var done bool
	start := time.Now()
	var eipCheckFailed bool
	var startupLatencySet bool
	// bufferedFailures holds post-startup failures not yet classified as random or failover-window.
	// Classified retroactively once the next successful parseable response arrives:
	//   - next IP is EgressIP     → random/transient (resolved without failover)
	//   - next IP is not EgressIP → failover-window (gap between EIP drop and next assignment)
	var bufferedFailures float64
	client := getHTTPClient(timeout)

	for !done {
		select {
		case <-stop:
			done = true
		default:
			url := buildDstURL(extHost, extPort)
			res, err := client.Get(url)

			if err != nil {
				// Connection-level failure: could not reach the external server at all.
				log.Printf("Error: Failed to talk to %q: %v", url, err)
				if !startupLatencySet {
					(*failure).Inc()
				} else {
					bufferedFailures++
				}
			} else if res.StatusCode != http.StatusOK {
				// Reached the server but got an unexpected status code.
				log.Printf("Error: Unexpected status code %d from %q", res.StatusCode, url)
				res.Body.Close()
				if !startupLatencySet {
					(*failure).Inc()
				} else {
					bufferedFailures++
				}
			} else {
				resBody, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil {
					log.Printf("Error: %v, while calling io.ReadAll", err)
					if !startupLatencySet {
						(*failure).Inc()
					} else {
						bufferedFailures++
					}
				} else {
					sourceIP := strings.TrimSpace(string(resBody))
					validIP, isEgress := parseAndCheckEgressIP(sourceIP, egressIPs)

					if !validIP {
						// Response body is not a parseable IP — treat as a request-level failure,
						// not a failover signal, to avoid skewing recovery latency.
						log.Printf("Error: unparseable IP in response body %q", sourceIP)
						if !startupLatencySet {
							(*failure).Inc()
						} else {
							bufferedFailures++
						}
					} else if !startupLatencySet {
						// Startup phase: waiting to see EgressIP for the first time.
						if isEgress {
							(*eipStartUpLatency).Set(time.Since(start).Seconds())
							log.Printf("Startup Latency: %v seconds", time.Since(start).Seconds())
							startupLatencySet = true
						}
						// Non-egress IP during startup is expected — EIP not yet assigned, nothing to record.
					} else {
						// Post-startup phase.
						if isEgress {
							// Flush buffered failures as random: resolved back to EgressIP without failover.
							if bufferedFailures > 0 {
								log.Printf("Flushing %v buffered failure(s) as random (resolved back to EgressIP)", bufferedFailures)
								(*randomFailure).Add(bufferedFailures)
								bufferedFailures = 0
							}
							if eipCheckFailed {
								// EIP just recovered from failover.
								eipCheckFailed = false
								(*eipRecoveryLatency).Set(time.Since(start).Seconds())
								log.Printf("Failover/Recovery Latency: %v seconds", time.Since(start).Seconds())
								start = time.Now()
							}
						} else {
							// Not EgressIP post-startup — failover is active.
							// Flush buffered failures as failover-window: they occurred in the gap
							// between EIP being dropped and the next IP being assigned.
							if bufferedFailures > 0 {
								log.Printf("Flushing %v buffered failure(s) as failover-window (resolved to non-EgressIP)", bufferedFailures)
								(*failoverWindowFailure).Add(bufferedFailures)
								bufferedFailures = 0
							}
							if !eipCheckFailed {
								// Failover just started; record the start time.
								eipCheckFailed = true
								start = time.Now()
							}
						}
					}
				}
			}

			if delayBetweenReq != 0 {
				time.Sleep(time.Duration(delayBetweenReq) * time.Second)
			}
		}
	}

	// Process stopping with unresolved buffered failures — no failover was confirmed,
	// so treat them as random.
	if bufferedFailures > 0 {
		log.Printf("Process stopping: flushing %v unclassified buffered failure(s) as random", bufferedFailures)
		(*randomFailure).Add(bufferedFailures)
	}

	log.Print("Finished polling source IP")
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

func processEnvVars() (string, string, string, int, int) {
	var err error
	extHost := os.Getenv(serverEnvKey)
	if extHost == "" {
		panic(fmt.Sprintf(envKeyErrMsg, serverEnvKey))
	}
	extPort := os.Getenv(portEnvKey)
	if extPort == "" {
		panic(fmt.Sprintf(envKeyErrMsg, portEnvKey))
	}
	egressIPsStr := os.Getenv(egressIPsEnvKey)
	if egressIPsStr == "" {
		panic(fmt.Sprintf(envKeyErrMsg, egressIPsEnvKey))
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
	return extHost, extPort, egressIPsStr, delayBetweenReq, requestTimeout
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

func buildAndRegisterMetrics(delayBetweenReq int) (*prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge, *prometheus.Gauge) {
	var eipStartUpLatency = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "eip_startup_latency_seconds",
		Help: fmt.Sprintf("time in seconds from process start until EgressIP is first seen as source IP"+
			" - polling interval %d seconds", delayBetweenReq),
	})

	var eipRecoveryLatency = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "eip_recovery_latency_seconds",
		Help: fmt.Sprintf("time in seconds from failover start (EgressIP last seen) until EgressIP is seen again"+
			" - polling interval %d seconds", delayBetweenReq),
	})

	var failure = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "failure_total",
		Help: fmt.Sprintf("connection failures, non-200 status codes, unreadable response bodies, or unparseable IPs"+
			" - polling interval %d seconds", delayBetweenReq),
	})

	var randomFailure = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "random_failure_total",
		Help: fmt.Sprintf("post-startup failures that resolved back to EgressIP — transient network issues unrelated to EIP failover"+
			" - polling interval %d seconds", delayBetweenReq),
	})

	var failoverWindowFailure = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scale",
		Name:      "failover_window_failure_total",
		Help: fmt.Sprintf("post-startup failures followed by a non-EgressIP response — occurred in the gap during EIP failover"+
			" - polling interval %d seconds", delayBetweenReq),
	})

	prometheus.MustRegister(eipStartUpLatency)
	prometheus.MustRegister(eipRecoveryLatency)
	prometheus.MustRegister(failure)
	prometheus.MustRegister(randomFailure)
	prometheus.MustRegister(failoverWindowFailure)
	return &eipStartUpLatency, &eipRecoveryLatency, &failure, &randomFailure, &failoverWindowFailure
}
