package dtls

import "github.com/icn-team/dtls/v2/pkg/protocol/recordlayer"

type packet struct {
	record                   *recordlayer.RecordLayer
	shouldEncrypt            bool
	resetLocalSequenceNumber bool
}
