
#define RADIOTAP_HEADER_LENGTH	    0x18
#define IEEE802_11_MAC_LENGTH	    0x06
#define CCMP_PARAMETER_LENGTH	    0x07

struct ieee80211_radiotap_hdr {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int8_t       dummy[7];     /* fields present */
} __attribute__((__packed__));

struct fixed_param{
        u_int16_t reason_code;
};

struct ieee80211_deauth_hdr{	//38
	u_int8_t version:2,
		  frame_type:2,
		  frame_subtype:4;
	u_int8_t flag;
	u_int16_t duration;
	
	u_int8_t addr1[IEEE802_11_MAC_LENGTH];
	u_int8_t addr2[IEEE802_11_MAC_LENGTH];
	u_int8_t addr3[IEEE802_11_MAC_LENGTH];

	u_int16_t numbers;	//data
	
	struct fixed_param fix;
	//std::list<tagged_param> tag;

};

typedef struct {
        char* dev_;
	char* ap_mac_;
	char* station_mac_;
	bool auth_;
} Param;

Param param  = {
        .dev_ = NULL,
	.ap_mac_ = NULL,
	.station_mac_ = NULL
};

enum tag_number{
	SSID_PARAMETER_SET = 0,
	SUPPORTED_RATES = 1,
	DS_PARAMETER_SET = 3,
	IBSS_PARAMETER_SET = 6,
	QBSS_LOAD_ELEMENT = 11,
	ERP_INFORMATION = 42,
	EXTENDED_SUPPORTED_RATES = 50,
	VENDOR_SPECIFIC = 221,

};


