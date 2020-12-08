#include <stdint.h>
#include "mac.h"

#pragma pack(push, 1)
struct radiotap_hdr final {
	u_int8_t        radhdr_version;     /* set to 0 */
        u_int8_t        radhdr_pad;
        u_int16_t       radhdr_len;         /* entire length */
        u_int32_t       radhdr_present;     /* fields present */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_frame {
	uint8_t		beafrm_type;
	uint8_t		beafrm_flags;
	uint16_t	beafrm_duration;
	Mac beafrm_rcv;
	Mac beafrm_src;
	Mac beafrm_bss;
	uint16_t	beafrm_frag_seq;
};
#pragma pack(pop)
