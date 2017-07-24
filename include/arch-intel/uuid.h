typedef struct __attribute__ ((packed)) {
	uint32_t    data1;
	uint16_t    data2;
	uint16_t    data3;
	uint16_t    data4;
 	uint8_t     data5[6];
} uuid_t;


static inline int are_uuids_equal(const uuid_t *uuid1, const uuid_t *uuid2)
{
	return (memcmp(uuid1, uuid2, sizeof(*uuid1)) == 0);
}

