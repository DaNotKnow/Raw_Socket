struct ipheader{
	unsigned int ip_version:4, ip_ihl:4;
	unsigned char ip_typeOfService;
	unsigned short int ip_totalLength;
	unsigned short int ip_identification;
	unsigned char ip_flags;
	unsigned short int ip_fragmentOffset;
	unsigned char ip_timeToLive;
	unsigned char ip_protocol;
	unsigned short int ip_headerChecksum;
	unsigned long int ip_sourceIpAddress;
	unsigned long int ip_destinationIpAddress;
};

struct udpheader{
	unsigned short int udp_sourcePortNumber;
	unsigned short int udp_destinationPortNumber;
	unsigned short int udp_length;
	unsigned short int udp_checksum;
};
