package dns

const (
	// OPCODE
	OpcodeQuery  byte = 0 // standard query
	OpcodeIquery byte = 1 // inverse query
	OpcodeStatus byte = 2 // server status query

	// QR
	Query    byte = 1 // query
	Response byte = 2 // response

	// RCODE
	RcodeNoError       byte = 0 // no error condition
	RcodeFormatError   byte = 1 // format errro, unable to interpret the query
	RcodeServerFailure byte = 2 // unable to process the query
	RcodeNameError     byte = 3 // meaningful only for responses from an
	// authoritative name server, signifies the domain
	// name referenced in the query does not exist
	RcodeNotImplemented byte = 4 // not support the requested kind of query
	RcodeRefused        byte = 5 // refuses to perform specified operation for policy reasons

	// CLASS
	IN  byte = 1   // internet
	CS  byte = 2   // CSNET
	CH  byte = 3   // CHAOS
	HS  byte = 4   // Hesiod
	ANY byte = 255 // any

	// TYPE
	A     byte = 1  // host address
	NS    byte = 2  // authoritative name server
	MD    byte = 3  // a mail destination (Obsolete, use MX)
	MF    byte = 4  // a mail forwarder (Obsolete, use MX)
	CNAME byte = 5  // canonical name for an alias
	SOA   byte = 6  // start of a zone of authority
	MB    byte = 7  // a mailbox domain name
	MG    byte = 8  // mail group member
	MR    byte = 9  // mail rename domain name
	NULL  byte = 10 // null RR
	WKS   byte = 11 // well known server description
	PTR   byte = 12 // a domain name pointer
	HINFO byte = 13 // host information
	MINFO byte = 14 // mailbox or mail list information
	MX    byte = 15 // mail exchange
	TXT   byte = 16 // text strings
)
