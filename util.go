package main

import (
	"encoding/json"
	"errors"
	"log"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/google/uuid"
)

var (
	invalidInputErr = errors.New("Invalid Input")
)

func logAsJson(obj any, GivenLogger *log.Logger) {
	objM, err := json.Marshal(obj)
	if err != nil {
		ErrLogger.Println("Error logging results: ", err)
		ErrLogger.Println(obj) // Dump results in non-JSON format
	}
	objString := string(objM)
	GivenLogger.Println(objString)
}

// validateForm validates user input obtained from /measure webpage
func validateForm(email string, expType string, locationVPN string, locationUser string) (*FormDetails, error) {
	if match, _ := regexp.MatchString(`^\w+@brave\.com$`, email); !match {
		return nil, invalidInputErr
	}
	if expType != "vpn" && expType != "direct" {
		return nil, invalidInputErr
	}
	if match, _ := regexp.MatchString(`^[\w,.'";:\s\d(){}]*$`, locationVPN); !match {
		return nil, invalidInputErr
	}
	if match, _ := regexp.MatchString(`^[\w,.'";:\s\d(){}]*$`, locationUser); !match {
		return nil, invalidInputErr
	}

	details := FormDetails{
		UUID:         uuid.NewString(),
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		Contact:      email,
		ExpType:      expType,
		LocationVPN:  locationVPN,
		LocationUser: locationUser,
	}
	return &details, nil
}

// isValidUUID checks if UUID u is valid
func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// fmtTimeMs returns the value (time.Duration) in milliseconds, the inbuilt time.Milliseconds() function only returns an int64 value
func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

// getSentTimestampfromIPId traverses the []SentPacketData slice and returns the HopSentTime associated with the provided ipid, and error if any
func getSentTimestampfromIPId(sentDataSlice []SentPacketData, ipid uint16) (time.Time, error) {
	for _, v := range sentDataSlice {
		if v.HopIPId == ipid {
			return v.HopSentTime, nil
		}
	}
	return time.Now().UTC(), errors.New("IP Id not in sent packets")
}

// getHeaderFromICMPResponsePayload parses IP headers from ICMP Response Payload of the icmpPkt and returns IP header, and error if any
func getHeaderFromICMPResponsePayload(icmpPkt []byte) (*layers.IPv4, error) {
	if len(icmpPkt) < 1 {
		return nil, errors.New("Invalid IP header")
	}
	ipHeaderLength := int((icmpPkt[0] & 0x0F) * 4)

	if len(icmpPkt) < ipHeaderLength {
		return nil, errors.New("IP header unavailable")
	}
	ip := layers.IPv4{}
	ipErr := ip.DecodeFromBytes(icmpPkt[0:], gopacket.NilDecodeFeedback)

	if ipErr != nil {
		return nil, ipErr
	}

	return &ip, nil
}

// sliceContains checks if a particular IP Id (uint16 in layers.IPv4) is present in the slice of IP Ids we provide
func sliceContains(slice []SentPacketData, value uint16) bool {
	for _, v := range slice {
		if v.HopIPId == value {
			return true
		}
	}
	return false
}