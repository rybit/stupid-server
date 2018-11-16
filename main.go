package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	io "github.com/graarh/golang-socketio"
	"github.com/graarh/golang-socketio/transport"
	"github.com/labstack/echo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var tlsConfig *tls.Config

func main() {
	root := cobra.Command{
		Use:  "server <port>",
		RunE: run,
	}

	root.PersistentFlags().BoolP("debug", "d", false, "enable debug logging")
	root.PersistentFlags().StringSliceP("path", "p", nil, "a path and response code together. ex: /something:200")

	root.PersistentFlags().String("tlscert", "", "the tls cert file to use")
	root.PersistentFlags().String("tlskey", "", "the tls key file to use")
	root.PersistentFlags().StringSlice("tlsca", nil, "the tls ca files to use")

	if c, err := root.ExecuteC(); err != nil {
		log.Fatalf("Failed to execute command %s - %s", c.Name(), err.Error())
	}
}

func run(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("wrong number of params")
	}
	port := args[0]

	loadConfiguration(cmd)
	l := logrus.WithField("port", port)

	server := echo.New()
	server.Debug = viper.GetBool("debug")
	paths, err := cmd.Flags().GetStringSlice("path")
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		paths = []string{"/:200"}
	}

	for _, p := range paths {
		parts := strings.Split(p, ":")
		if len(parts) != 2 {
			l.Warnf("Invalid path param '%s' - ignoring it", p)
			continue
		}

		rspCode, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			l.Warnf("Invalid path param '%s' - ignoring it", p)
			continue
		}

		l.Infof("Responding with %d to %s", rspCode, parts[0])
		rspLog := l.WithFields(logrus.Fields{
			"path": parts[0],
			"code": rspCode,
		})
		server.GET(parts[0], func(c echo.Context) error {
			rspLog.WithFields(logrus.Fields{
				"q": c.QueryString(),
			}).Info("got request: GET")
			dumpHeaders(rspLog, c.Request().Header)
			return c.NoContent(int(rspCode))
		})
		server.POST(parts[0], func(c echo.Context) error {
			rspLog.WithFields(logrus.Fields{
				"q": c.QueryString(),
			}).Info("got request: POST")
			req := c.Request()
			dumpHeaders(rspLog, req.Header)
			defer req.Body.Close()
			bs, err := ioutil.ReadAll(req.Body)
			if err != nil {
				rspLog.WithError(err).Warn("failed to extract body")
			} else {
				rspLog.Infof("Payload: \n%s", string(bs))
			}
			return c.NoContent(int(rspCode))
		})
	}
	server.GET("/*", func(c echo.Context) error {
		l.WithField("path", c.Request().URL.Path).Infof("unconfigured path '%s'", c.Request().URL.Path)
		return c.NoContent(http.StatusNotFound)
	})
	server.POST("/*", func(c echo.Context) error {
		l.WithField("path", c.Request().URL.Path).Infof("unconfigured path '%s'", c.Request().URL.Path)
		return c.NoContent(http.StatusNotFound)
	})

	l.Info("starting the server")
	if viper.GetString("tlscert") != "" {
		panic("not implemented")
		//server.Run(standard.WithTLS(fmt.Sprintf(":%s", port), viper.GetString("tlscert"), viper.GetString("tlskey")))
	} else {
		server.Start(fmt.Sprintf(":%s", port))
	}

	return nil
}

func loadConfiguration(cmd *cobra.Command) {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	viper.BindPFlags(cmd.PersistentFlags())
	viper.BindPFlags(cmd.Flags())

	if viper.GetBool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	//if viper.GetString("tlscert") != "" {
	//	var err error
	//	tlsConfig, err = getTLS(viper.GetString("tlscert"), viper.GetString("tlskey"), viper.GetStringSlice("tlsca"))
	//	if err != nil {
	//		logrus.WithError(err).Fatal("Failed to configure tls")
	//	}
	//}
}

func connect(url string) (*io.Client, error) {
	client, err := io.Dial(url, transport.GetDefaultWebsocketTransport())
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getTLS(certFile, keyFile string, caFiles []string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	for _, caFile := range caFiles {
		caData, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}

		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("Failed to add CA cert at %s", caFile)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}

func dumpHeaders(log *logrus.Entry, h http.Header) {
	log.Infof("Headers: %+v\n", h)
}
