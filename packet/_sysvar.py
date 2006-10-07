
# OpenBSD Constants

#net/pfvar.h
PFRES_MATCH         = 0    # Explicit match of a rule
PFRES_BADOFF        = 1    # Bad offset for pull_hdr
PFRES_FRAG          = 2    # Dropping following fragment
PFRES_SHORT         = 3    # Dropping short packet
PFRES_NORM          = 4    # Dropping by normalizer
PFRES_MEMORY        = 5    # Dropped due to lacking mem
PFRES_TS            = 6    # Bad TCP Timestamp (RFC1323)
PFRES_CONGEST       = 7    # Congestion (of ipintrq)
PFRES_IPOPTIONS     = 8    # IP option
PFRES_PROTCKSUM     = 9    # Protocol checksum invalid
PFRES_BADSTATE      = 10   # State mismatch
PFRES_STATEINS      = 11   # State insertion failure
PFRES_MAXSTATES     = 12   # State limit
PFRES_SRCLIMIT      = 13   # Source node/conn limit
PFRES_SYNPROXY      = 14   # SYN proxy

PFACT_PASS              = 0
PFACT_DROP              = 1
PFACT_SCRUB             = 2
PFACT_NOSCRUB           = 3
PFACT_NAT               = 4
PFACT_NONAT             = 5
PFACT_BINAT             = 6
PFACT_NOBINAT           = 7
PFACT_RDR               = 8
PFACT_NORDR             = 9
PFACT_SYNPROXY_DROP     = 10

PFDIR_INOUT             = 0
PFDIR_IN                = 1
PFDIR_OUT               = 2

# net/if.h
IFNAMSIZ                = 16

# net/if_pflog.h
PF_RULESET_NAME_SIZE    = 16
