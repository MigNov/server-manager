//#define DEBUG_BASE64

#include "manager.h"

#ifdef DEBUG_BASE64
#define DPRINTF(fmt, args...) \
do { printf("base64: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

#define XX 100

static const char base64_list[] = \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int base64_index[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};

void base64_encode_block(unsigned char out[4], const unsigned char in[3], int len)
{
	DPRINTF("%s: Input = { %02x, %02x, %02x }\n", __FUNCTION__, in[0], in[1], in[2]);

        out[0] = base64_list[ in[0] >> 2 ];
        out[1] = base64_list[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
        out[2] = (unsigned char) (len > 1 ? base64_list[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
        out[3] = (unsigned char) (len > 2 ? base64_list[in[2] & 0x3f] : '=');

	DPRINTF("%s: Output = { %02x, %02x, %02x, %02x }\n", __FUNCTION__, out[0], out[1], out[2], out[3]);
}

int base64_decode_block(unsigned char out[3], const unsigned char in[4], int is_last)
{
        int i, numbytes = 3;
        char tmp[4];

	DPRINTF("%s: Input = { %02x, %02x, %02x, %02x }\n", __FUNCTION__, in[0], in[1], in[2], in[3]);

        for(i = 3; i >= 0; i--) {
                if(in[i] == '=') {
                        tmp[i] = 0;
                        numbytes = i - 1;
                } else {
                        tmp[i] = base64_index[ (unsigned char)in[i] ];
                }
                
                if(tmp[i] == XX) {
			DPRINTF("%s: Invalid character on position %d\n", __FUNCTION__, i);
			if (is_last) {
				DPRINTF("%s: Incomplete block, continuing...\n", __FUNCTION__);
				tmp[i] = 0;
				break;
			}
			return(-1);
		}
        }

        out[0] = (unsigned char) (  tmp[0] << 2 | tmp[1] >> 4);
        out[1] = (unsigned char) (  tmp[1] << 4 | tmp[2] >> 2);
        out[2] = (unsigned char) (((tmp[2] << 6) & 0xc0) | tmp[3]);

	DPRINTF("%s: Output = { %02x, %02x, %02x }\n", __FUNCTION__, out[0], out[1], out[2]);

        return(numbytes);
}

size_t base64_encoded_size(size_t len)
{
        return(((len + 2) / 3) * 4);
}

size_t base64_decoded_size(size_t len)
{
        return((len / 4) * 3);
}

void base64_encode_binary(unsigned char *out, unsigned char *in, size_t len)
{
        int size;
        size_t i = 0;
        
        while(i < len) {
                size = (len-i < 4) ? len-i : 4;
                
                base64_encode_block((unsigned char *)out, in, size);

                out += 4;
                in  += 3;
                i   += 3;
        }

        *out = '\0';
}

int base64_decode_binary(unsigned char *out, const char *in)
{
        size_t len = strlen(in), i = 0;
        int numbytes = 0;

        while(i < len) {
                if((numbytes += base64_decode_block(out, (unsigned char *)in, i > len - 4)) < 0)
                        return(-1);

                out += 3;
                in  += 4;
                i   += 4;
        }

        return(numbytes);
}

unsigned char *base64_encode(const char *in, size_t *size)
{
        unsigned char *out;
        size_t outlen;
	size_t esize;

        if((in == NULL) || (size == NULL))
                return(NULL);

        esize = *size;
        if(esize == 0)
                esize = strlen(in);

        outlen = base64_encoded_size(esize);

        if((out = (unsigned char *)malloc(sizeof(unsigned char) * (outlen + 1))) == NULL)
                return(NULL);

        base64_encode_binary(out, (unsigned char *)in, esize);

	*size = outlen;

        return(out);
}

char *base64_decode(char *in)
{
        char *out;
        size_t outlen, size;
        int numbytes;
        
	size = strlen(in);
	DPRINTF("%s: Setting size to %d\n", __FUNCTION__, size);

        outlen = base64_decoded_size(size);

	DPRINTF("%s: Decoded size is %d bytes\n", __FUNCTION__, outlen);

        if((out = (unsigned char *)malloc(sizeof(unsigned char) * (outlen + 1))) == NULL)
                return(NULL);

	memset(out, 0, outlen + 1);

        if((numbytes = base64_decode_binary((unsigned char *)out, in)) < 0) {
                free(out);
                return(NULL);
        }

	DPRINTF("%s: Numbytes is %d bytes\n", __FUNCTION__, numbytes);

        *(out + numbytes) = '\0';
	size = outlen;
        
        return(out);
}

