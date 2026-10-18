package canonical

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Namespace UUIDs are wire constants, not installation-specific configuration.
// They are UUIDv5(URL namespace, the documented repository stream URL).
const NS_AGENTARIUM_KERNEL = "62aec079-204c-5723-a898-7fa567e82eb4"
const NS_AGENTARIUM_LIFECYCLE = "690f05df-a5fe-51bb-8f23-99c4492afc61"
const NS_AGENTARIUM_NETPOL = "83cab43f-080b-5fba-830d-37c97ec7be5c"
const maxObservationSequence int64 = 9007199254740991

func observationName(source, epoch string, sequence int64) (string, error) {
	if source == "" || epoch == "" || !utf8.ValidString(source) || !utf8.ValidString(epoch) || strings.Contains(epoch, "/") || len(source) > 16384 || len(epoch) > 16384 || sequence < 1 || sequence > maxObservationSequence {
		return "", errors.New("invalid observation identity")
	}
	return source + "/" + epoch + "/" + strconv.FormatInt(sequence, 10), nil
}
func KernelEventID(sensorID, epoch string, sequence int64) (string, error) {
	name, err := observationName(sensorID, epoch, sequence)
	if err != nil {
		return "", err
	}
	return uuid.NewSHA1(uuid.MustParse(NS_AGENTARIUM_KERNEL), []byte(name)).String(), nil
}
func LifecycleEventID(sourceID, epoch string, sequence int64) (string, error) {
	name, err := observationName(sourceID, epoch, sequence)
	if err != nil {
		return "", err
	}
	return uuid.NewSHA1(uuid.MustParse(NS_AGENTARIUM_LIFECYCLE), []byte(name)).String(), nil
}

// NetworkPolicyRecordID is COMMON NetworkPolicyRecord.record_id:
// UUIDv5(NS_AGENTARIUM_NETPOL, "cluster_uid/node_uid/source_epoch/source_sequence").
// Both UUIDs must be canonical lowercase so one record has one name.
func NetworkPolicyRecordID(clusterUID, nodeUID, epoch string, sequence int64) (string, error) {
	for _, id := range []string{clusterUID, nodeUID} {
		u, err := uuid.Parse(id)
		if err != nil || u == uuid.Nil || u.String() != id {
			return "", errors.New("invalid network policy record identity")
		}
	}
	name, err := observationName(clusterUID+"/"+nodeUID, epoch, sequence)
	if err != nil {
		return "", err
	}
	return uuid.NewSHA1(uuid.MustParse(NS_AGENTARIUM_NETPOL), []byte(name)).String(), nil
}

// AbandonedRangeDigest binds a range to its authenticated producer and stream.
// SourceID must come from the server's mTLS registration when verifying a batch.
// It adds no range-reason enum; callers enforce their own approved reason set.
func AbandonedRangeDigest(sourceID, stream, epoch string, from, to int64, reason string) (string, error) {
	if _, err := observationName(sourceID, epoch, from); err != nil {
		return "", err
	}
	if (stream != "kernel" && stream != "lifecycle" && stream != "network_policy") || to < from || to > maxObservationSequence || reason == "" || !utf8.ValidString(reason) || len(reason) > 16384 {
		return "", errors.New("invalid abandoned range")
	}
	return CanonicalDigest(map[string]any{"source_id": sourceID, "stream": stream, "source_epoch": epoch, "from_seq": from, "to_seq": to, "reason": reason})
}
