package secrets

import (
	"context"
	"encoding/base64"
	"hash/crc32"
	"regexp"

	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/broker"
	sm "google.golang.org/api/secretmanager/v1"
)

var versionResource = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+/versions/[0-9]+$`)
var crcTable = crc32.MakeTable(crc32.Castagnoli)

type Google struct{ Service *sm.Service }

func (g Google) Access(ctx context.Context, name string) ([]byte, error) {
	if g.Service == nil || !versionResource.MatchString(name) {
		return nil, broker.ErrUnavailable
	}
	response, e := g.Service.Projects.Secrets.Versions.Access(name).Context(ctx).Do()
	if e != nil || response.Payload == nil || response.Name != name {
		return nil, broker.ErrUnavailable
	}
	data, e := base64.StdEncoding.Strict().DecodeString(response.Payload.Data)
	if e != nil || len(data) > broker.MaxHeaderBytes || int64(crc32.Checksum(data, crcTable)) != response.Payload.DataCrc32c {
		clear(data)
		return nil, broker.ErrUnavailable
	}
	return data, nil
}
