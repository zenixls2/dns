package dns

import "fmt"

/*
Refer to https://www.ietf.org/rfc/rfc1035.txt
From section 4.1.1
The header contains the following fields:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

type Header struct {
	// created by app for request identification
	// forwareded back in response to match
	ID uint16

	// 1bit, query(0) or response(1)
	QR uint8

	// 4bit for query type
	// 0 - standard query (QUERY)
	// 1 - inverse query (IQUERY)
	// 2 - server status request (STATUS)
	// 3~15 - reserved for future use
	Opcode uint8

	// 1bit, Answer or Authoritative
	AA uint8

	// 1bit, Truncated message or not
	TC uint8

	// 1bit, Recursion is Desired or not
	RD uint8

	// 1bit, Recursion is Available or not
	RA uint8

	// 1bit, future use
	Z uint8

	// 4bit, Response code
	RCODE uint8

	// number of entries in question section
	QDCOUNT uint16

	// number of resource records in answer section
	ANCOUNT uint16

	// number of name server resource records in authority section
	NSCOUNT uint16

	// number of resource records in additional records section
	ARCOUNT uint16
}

func NewHeader() (h *Header) {
	return &Header{}
}

func (h *Header) Unmarshal(msg []byte) (n int, err error) {
	if h == nil {
		h = &Header{}
	}
	if len(msg) != 12 {
		err = fmt.Errorf("msg doesn't have expected size %d", len(msg))
		return
	}
	var highbyte, lowbyte byte
	h.ID = uint16(msg[1]) | (uint16(msg[0]) << 8)
	highbyte = msg[2]
	lowbyte = msg[3]
	h.RD = highbyte & 0x1
	h.TC = (highbyte >> 1) & 0x1
	h.AA = (highbyte >> 2) & 0x1
	h.Opcode = (highbyte >> 3) & 0xF
	h.QR = (highbyte >> 7) & 0x1
	h.RCODE = lowbyte & 0xF
	h.Z = (lowbyte >> 4) & 0xF
	h.RA = (lowbyte >> 7) & 0x1
	h.QDCOUNT = uint16(msg[5]) | (uint16(msg[4]) << 8)
	h.ANCOUNT = uint16(msg[7]) | (uint16(msg[6]) << 8)
	h.NSCOUNT = uint16(msg[9]) | (uint16(msg[8]) << 8)
	h.ARCOUNT = uint16(msg[11]) | (uint16(msg[10]) << 8)
	n = 12
	return
}

func (h *Header) Marshal() (result []byte) {
	result = make([]byte, 12, 12)
	result[0] = uint8(h.ID >> 8)
	result[1] = uint8(h.ID)
	result[2] = (h.QR << 7) | (h.Opcode << 3) | (h.AA << 2) | (h.TC << 1) | h.RD
	result[3] = (h.RA << 7) | (h.Z << 4) | h.RCODE
	result[4] = uint8(h.QDCOUNT >> 8)
	result[5] = uint8(h.QDCOUNT)
	result[6] = uint8(h.ANCOUNT >> 8)
	result[7] = uint8(h.ANCOUNT)
	result[8] = uint8(h.NSCOUNT >> 8)
	result[9] = uint8(h.NSCOUNT)
	result[10] = uint8(h.ARCOUNT >> 8)
	result[11] = uint8(h.ARCOUNT)
	return
}

/*
The question section is used to carry the "question" in most queries,
i.e., the parameters that define what is being asked.  The section
contains QDCOUNT (usually 1) entries, each of the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type Question struct {

	//a domain name represented as a sequence of labels, where
	// each label consists of a length octet followed by that
	// number of octets.  The domain name terminates with the
	// zero length octet for the null label of the root.  Note
	// that this field may be an odd number of octets; no
	// padding is used.
	QNAME [][]byte

	// Query type, valid values are:
	// 1: A, a host address
	// 2: NS, an authoritative name server
	// 3: MD, a mail destination (Obsolete - use MX)
	// 4: MF, a mail forwarder (Obsolete - use MX)
	// 5: CNAME, the canonical name for an alias
	// 6: SOA, marks the start of a zone of authority
	// 7: MB, a mailbox domain name (EXPERIMENTAL)
	// 8: MG, a mailgroup member (EXPERIMENTAL)
	// 9: MR, a mail rename domain name (EXPERIMENTAL)
	// 10: NULL, a null RR(EXPERIMENTAL)
	// 11: WKS, a well known service description
	// 12: PTR, a domain name pointer
	// 13: HINFO, host information
	// 14: MINFO, mailbox or mail list information
	// 15: MX, mail exchange
	// 16: TXT, text strings
	// *252: AXFR, a request for a transfer of an entire zone
	// *253: MAILB, a request for mailbox-related records (MB, MG or MR)
	// *254: MAILA, a request for mail agent RRs (Obsolete - see MX)
	// *255: *, a request for all records
	QTYPE uint16

	// Query Class values
	// 1: IN, the internet
	// 2: CS, the CSNET class (Obsolete - used only for examples in some
	// obsolete RFCs)
	// 3: CH, the CHAOS class
	// 4: HS, Hesiod [Dyer 87]
	// *255: *, any class
	QCLASS uint16
}

func NewQuestion() *Question {
	return &Question{
		QNAME:  make([][]byte, 0, 3),
		QTYPE:  0,
		QCLASS: 0,
	}
}

func (q *Question) Unmarshal(msg []byte) (index int, err error) {
	if q == nil {
		q = NewQuestion()
	}
	var size int
	index = 0
	for {
		size = int(msg[index])
		// compression check and extraction
		if size&0xB0 == 0xB0 {
			offset := size & 0x3F
			q.QNAME = append(q.QNAME, q.QNAME[offset])
			index += 1
			continue
		}
		if size == 0 {
			index += 1
			break
		}
		q.QNAME = append(q.QNAME, msg[index+1:index+size+1])
		index += (size + 1)
	}
	q.QTYPE = uint16(msg[index+1]) | (uint16(msg[index]) << 8)
	q.QCLASS = uint16(msg[index+3]) | (uint16(msg[index+2]) << 8)
	index += 4
	return
}

func (q *Question) Marshal() (result []byte, err error) {
	result = make([]byte, 0, 8)
	if len(q.QNAME) < 2 {
		if len(q.QNAME) == 1 {
			err = fmt.Errorf("mailformed qname %s", string(q.QNAME[0]))
		} else {
			err = fmt.Errorf("mailformed qname")
		}
		return
	}
	var length int
	for _, name := range q.QNAME {
		length = len(name)
		if length == 0 {
			err = fmt.Errorf("cannot have empty label")
			return
		}
		// first 2 bits must be zero
		if length > 63 {
			err = fmt.Errorf("label length larger than 63: %s", string(name))
			return
		}
		result = append(result, byte(length))
		result = append(result, name...)
	}
	result = append(result,
		byte(q.QTYPE>>8), byte(q.QTYPE),
		byte(q.QCLASS>>8), byte(q.QCLASS),
	)
	return
}

/*
All RRs have the same top level format shown below:
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type RR struct {
	NAME     [][]byte
	TYPE     uint16
	CLASS    uint16
	TTL      int32
	RDLENGTH uint16
	RDATA    []byte
}

func NewRR() *RR {
	return &RR{
		NAME:     make([][]byte, 0, 6),
		TYPE:     0,
		CLASS:    0,
		TTL:      0,
		RDLENGTH: 0,
		RDATA:    []byte{},
	}
}

func (r *RR) Unmarshal(msg []byte) (index int, err error) {
	if r == nil {
		r = NewRR()
	}
	if len(msg) < 11 {
		err = fmt.Errorf("rr msg must be at least 11 bytes long")
		return
	}
	var size int
	var offset int
	index = 0
	for {
		size = int(msg[index])
		// compression check and extraction
		if size&0xB0 == 0xB0 {
			offset = size & 0x3F
			r.NAME = append(r.NAME, r.NAME[offset])
			index += 1
			continue
		}
		if size == 0 {
			index += 1
			break
		}
		r.NAME = append(r.NAME, msg[index+1:index+size+1])
		index += (size + 1)
	}
	r.TYPE = uint16(msg[index+1]) | (uint16(msg[index]) << 8)
	r.CLASS = uint16(msg[index+3]) | (uint16(msg[index+2]) << 8)
	r.TTL = (int32(msg[index+4]) << 24) | (int32(msg[index+5]) << 16) | (int32(msg[index+6]) << 8) | int32(msg[index+7])
	r.RDLENGTH = (uint16(msg[index+8]) << 8) | uint16(msg[index+9])
	r.RDATA = msg[index+10 : index+10+int(r.RDLENGTH)]
	index += 11 + int(r.RDLENGTH)
	return
}

func (r *RR) Marshal() (result []byte, err error) {
	result = make([]byte, 0, 12)
	for _, name := range r.NAME {
		length := len(name)
		if length == 0 {
			err = fmt.Errorf("cannot have empty label")
			return
		}
		// first 2 bits must be zero
		if length > 63 {
			err = fmt.Errorf("label length larger than 63: %s", string(name))
			return
		}
		// no support compression currently
		result = append(result, byte(length))
		result = append(result, name...)
	}
	result = append(result,
		byte(r.TYPE>>8), byte(r.TYPE),
		byte(r.CLASS>>8), byte(r.CLASS),
		byte(r.TTL>>24), byte(r.TTL>>16),
		byte(r.TTL>>8), byte(r.TTL),
		byte(r.RDLENGTH>>8), byte(r.RDLENGTH),
	)
	result = append(result, r.RDATA...)
	return
}

type Message struct {
	Header
	Questions   []*Question
	Answers     []*RR
	NameServers []*RR
	Additional  []*RR
}

func (dns *Message) Unmarshal(msg []byte) (err error) {
	index := 0
	offset, err := dns.Header.Unmarshal(msg[index:len(msg)])
	if err != nil {
		return
	}
	index += offset
	dns.Questions = nil
	var q *Question
	for i := 0; i < int(dns.Header.QDCOUNT); i++ {
		q = NewQuestion()
		offset, err = q.Unmarshal(msg[index:len(msg)])
		// the QDCOUNT value is fake
		if offset == 0 {
			dns.Header.QDCOUNT = uint16(i)
			break
		}
		if err != nil {
			return
		}
		dns.Questions = append(dns.Questions, q)
		index += offset
	}

	dns.Answers = nil
	for i := 0; i < int(dns.Header.ANCOUNT); i++ {
		var a *RR
		a = NewRR()
		offset, err = a.Unmarshal(msg[index:len(msg)])
		// the ANCOUNT value is fake
		if offset == 0 {
			dns.Header.ANCOUNT = uint16(i)
			break
		}
		if err != nil {
			return
		}
		dns.Answers = append(dns.Answers, a)
		index += offset
	}

	dns.NameServers = nil
	for i := 0; i < int(dns.Header.NSCOUNT); i++ {
		var ns *RR
		ns = NewRR()
		offset, err = ns.Unmarshal(msg[index:len(msg)])
		// the NSCOUNT value is fake
		if offset == 0 {
			dns.Header.NSCOUNT = uint16(i)
			break
		}
		if err != nil {
			return
		}
		dns.NameServers = append(dns.NameServers, ns)
		index += offset
	}

	dns.Additional = nil
	for i := 0; i < int(dns.Header.ARCOUNT); i++ {
		var ar *RR
		ar = NewRR()
		offset, err = ar.Unmarshal(msg[index:len(msg)])
		// the ARCOUNT value is fake
		if offset == 0 {
			dns.Header.ARCOUNT = uint16(i)
		}
		if err != nil {
			return
		}
		dns.Additional = append(dns.Additional, ar)
		index += offset
	}
	return
}
