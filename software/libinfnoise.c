/* Library for the Infinite Noise Multiplier USB stick */

// Required to include clock_gettime
#define _POSIX_C_SOURCE 200809L

#define INFNOISE_VENDOR_ID 0x0403
#define INFNOISE_PRODUCT_ID 0x6015

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ftdi.h>
#include "libinfnoise_private.h"
#include "libinfnoise.h"
#include "blake2.h"
#include "blake2-impl.h"

blake2xb_state b2xb[1];
bool initInfnoise(struct ftdi_context *ftdic,char *serial, char **message, bool hash, bool debug, uint32_t outlen) {
    prepareOutputBuffer();

    // initialize health check
    if (!inmHealthCheckStart(PREDICTION_BITS, DESIGN_K, debug)) {
        *message="Can't initialize health checker";
        return false;
    }

    // initialize USB
    if(!initializeUSB(ftdic, message, serial)) {
        // Sometimes have to do it twice - not sure why
        if(!initializeUSB(ftdic, message, serial)) {
            return false;
        }
    }

    // initialize blake2, as stated by blake2x document, XOF digest length can be up to 2^32-2 (0xFFFFFFFEUL) for
    // predefined output length (max. 4GiB output), set that to 2^32 - 1 if "output length not known in advance"
    // or "require > 4GiB output (max. 256GiB)"
    if (hash) {
        if (outlen == 0 || outlen > 0xFFFFFFFEUL) {
            blake2xb_init(b2xb, 0xFFFFFFFFUL);
        } else {
            blake2xb_init(b2xb, outlen);
        }
    }

    // let healthcheck collect some data
    uint32_t maxWarmupRounds = 500;
    uint32_t warmupRounds = 0;
    bool errorFlag = false;
    while(!inmHealthCheckOkToUseData()) {
        readData_private(ftdic, NULL, message, &errorFlag, false, true, 0, false);
        warmupRounds++;
    }
    if (warmupRounds > maxWarmupRounds) {
        *message = "Unable to collect enough entropy to initialize health checker.";
        return false;
    }
    return true;
}

uint8_t outBuf[BUFLEN];
void prepareOutputBuffer() {
    uint32_t i;

    // Endless loop: set SW1EN and SW2EN alternately
    for(i = 0u; i < BUFLEN; i++) {
        // Alternate Ph1 and Ph2
        outBuf[i] = i & 1?  (1 << SWEN2) : (1 << SWEN1);
    }
}

// Extract the INM output from the data received.  Basically, either COMP1 or COMP2
// changes, not both, so alternate reading bits from them.  We get 1 INM bit of output
// per byte read.  Feed bits from the INM to the health checker.  Return the expected
// bits of entropy.
uint32_t extractBytes(uint8_t *bytes, uint8_t *inBuf, char **message, bool *errorFlag) {
    inmClearEntropyLevel();
    uint32_t i;
    for(i = 0u; i < BUFLEN/8u; i++) {
        uint32_t j;
        uint8_t byte = 0u;
        for(j = 0u; j < 8u; j++) {
            uint8_t val = inBuf[i*8u + j];
            uint8_t evenBit = (val >> COMP2) & 1u;
            uint8_t oddBit = (val >> COMP1) & 1u;
            bool even = j & 1u; // Use the even bit if j is odd
            uint8_t bit = even? evenBit : oddBit;
            byte = (byte << 1u) | bit;

            // This is a good place to feed the bit from the INM to the health checker.
            if(!inmHealthCheckAddBit(evenBit, oddBit, even)) {
                *message = "Health check of Infinite Noise Multiplier failed!";
		*errorFlag = true;
                return 0;
            }
        }
        bytes[i] = byte;
    }
    return inmGetEntropyLevel();
}

// Return the difference in the times as a double in microseconds.
double diffTime(struct timespec *start, struct timespec *end) {
    uint32_t seconds = end->tv_sec - start->tv_sec;
    int32_t nanoseconds = end->tv_nsec - start->tv_nsec;
    return seconds*1.0e6 + nanoseconds/1000.0;
}

// Write the bytes to either stdout, or /dev/random.
bool outputBytes(uint8_t *bytes,  uint32_t length, uint32_t entropy, bool writeDevRandom, char **message) {
    if(!writeDevRandom) {
        if(fwrite(bytes, 1, length, stdout) != length) {
            *message = "Unable to write output from Infinite Noise Multiplier";
            return false;
        }
    } else {
        inmWaitForPoolToHaveRoom();
        inmWriteEntropyToPool(bytes, length, entropy);
    }
    return true;
}

bool isSuperUser(void) {
        return (geteuid() == 0);
}

//customized final function to get partial output without changing blake2's underlying maths
int blake2xb_inm_final( blake2xb_state *S, uint8_t *result, void *out, size_t outlen, uint32_t entropy,
    bool writeDevRandom, uint32_t *bytesWritten, bool noOutput, char **message, bool *errorFlag) {
  //add out variables

  blake2b_state C[1];
  blake2b_param P[1];
  uint32_t xof_length = load32(&S->P->xof_length);
  uint8_t root[BLAKE2B_BLOCKBYTES];
  size_t i;
  if (NULL == out) {
    return -1;
  }
  /* outlen must match the output size defined in xof_length, */
  /* unless it was -1, in which case anything goes except 0. */
  if(xof_length == 0xFFFFFFFFUL) {
    if(outlen == 0) {
      return -1;
    }
  } else {
    if(outlen != xof_length) {
      return -1;
    }
  }
  /* Finalize the root hash */
  if (blake2b_final(S->S, root, BLAKE2B_OUTBYTES) < 0) {
    return -1;
  }
  /* Set common block structure values */
  /* Copy values from parent instance, and only change the ones below */
  memcpy(P, S->P, sizeof(blake2b_param));
  P->key_length = 0;
  P->fanout = 0;
  P->depth = 0;
  store32(&P->leaf_length, BLAKE2B_OUTBYTES);
  P->inner_length = BLAKE2B_OUTBYTES;
  P->node_depth = 0;
  for (i = 0; outlen > 0; ++i) {
    const size_t block_size = (outlen < BLAKE2B_OUTBYTES) ? outlen : BLAKE2B_OUTBYTES;
    /* Initialize state */
    P->digest_length = block_size;
    store32(&P->node_offset, i);
    blake2b_init_param(C, P);
    /* Process key if needed */
    blake2b_update(C, root, BLAKE2B_OUTBYTES);
    // here starts the modification, use a small buffer to receive partial result
    // and output it as normal (as used in keccak version)
    if (blake2b_final(C, (uint8_t *)out, block_size) < 0 ) {
        return -1;
    }
    uint32_t entropyThisTime = entropy;
    if (entropyThisTime > 8u*block_size) {
        entropyThisTime = 8u*block_size;
    }
    if (!noOutput) {
        if (!outputBytes(out, block_size, entropyThisTime, writeDevRandom, message)) {
            *errorFlag = true;
            return 0;
        }
    } else {
        if (result != NULL) {
            for (uint32_t j = 0; j < block_size; j++) {
                result[*bytesWritten + j] = ((uint8_t *)out)[j];
            }
        }
    }
    *bytesWritten += block_size;
    entropy -= entropyThisTime;
    //modification ends
    outlen -= block_size;
  }
  secure_zero_memory(root, sizeof(root));
  secure_zero_memory(P, sizeof(P));
  secure_zero_memory(C, sizeof(C));
  /* Put blake2xb in an invalid state? cf. blake2s_is_lastblock */
  return 0;
}

// Whiten the output, if requested, with a blake2xb state. Output bytes only if
// the health checker says it's OK.  Use outputLength to generate a lot more
// cryptographically secure pseudo-random data than the INM generates.  If
// outputMultiplier is 0, we output only as many bits as we measure in entropy.
// This allows a user to generate hundreds of MiB per second if needed, for use
// as cryptographic keys.
uint32_t processBytes(uint8_t *bytes, uint8_t *result, uint32_t entropy,
        bool raw, bool writeDevRandom, uint32_t outputLength, bool noOutput,
        char **message, bool *errorFlag) {
    //Use the lower of the measured entropy and the provable lower bound on
    //average entropy.
    if(entropy > inmExpectedEntropyPerBit*BUFLEN/INM_ACCURACY) {
        entropy = inmExpectedEntropyPerBit*BUFLEN/INM_ACCURACY;
    }
    if(raw) {
        // In raw mode, we just output raw data from the INM.
        if (!noOutput) {
            if (!outputBytes(bytes, BUFLEN/8u, entropy, writeDevRandom, message)) {
		*errorFlag = true;
                return 0; // write failed
            }
        } else {
	    if (result != NULL) {
                memcpy(result, bytes, BUFLEN/8u * sizeof(uint8_t));
            }
	}
        return BUFLEN/8u;
    }

    // reseed before reaching max. output
    blake2xb_update(b2xb, bytes, BUFLEN/8u);
    uint8_t dataOut[16u*8u];
    if(outputLength == 0u) {
        // Output all the bytes of entropy we have
        blake2xb_final(b2xb, dataOut, entropy/8u);
    	if (!noOutput) {
    	    if (!outputBytes(dataOut, entropy/8u, entropy & 0x7u, writeDevRandom, message)) {
                    *errorFlag = true;
                    return 0;
                }
    	} else {
    	    if (result != NULL) {
                    memcpy(result, dataOut, entropy/8u * sizeof(uint8_t));
                }
    	}
        return entropy/8u;
    }else{
        // Output [outputLength] bytes.
        uint32_t bytesWritten = 0u;
        blake2xb_inm_final(b2xb, result, dataOut, outputLength, entropy, writeDevRandom, &bytesWritten, noOutput, message, errorFlag);
        if (*errorFlag == true) {
            return 0;
        }

        if(bytesWritten != outputLength) {
            *message = "Internal error outputing bytes";
    	*errorFlag = true;
            return 0;
        }
        return bytesWritten;
    }
}

// Return a list of all infinite noise multipliers found.
bool listUSBDevices(struct ftdi_context *ftdic, char** message) {
    ftdi_init(ftdic);

    struct ftdi_device_list *devlist;
    struct ftdi_device_list *curdev;
    char manufacturer[128], description[128], serial[128];
    int i=0;

    // search devices
    int rc = ftdi_usb_find_all(ftdic, &devlist, INFNOISE_VENDOR_ID, INFNOISE_PRODUCT_ID);

    if (rc < 0) {
        if (!isSuperUser()) {
            *message = "Can't find Infinite Noise Multiplier.  Try running as super user?";
        } else {
            *message = "Can't find Infinite Noise Multiplier";
        }
    }

    for (curdev = devlist; curdev != NULL; i++) {
        //printf("Device: %d, ", i);
        rc = ftdi_usb_get_strings(ftdic, curdev->dev, manufacturer, 128, description, 128, serial, 128);
        if (rc < 0) {
            if (!isSuperUser()) {
                *message = "Can't find Infinite Noise Multiplier.  Try running as super user?";
		return false;
            }
            //*message = "ftdi_usb_get_strings failed: %d (%s)\n", rc, ftdi_get_error_string(ftdic));
	    return false;
       	}

	// print to stdout
        printf("Manufacturer: %s, Description: %s, Serial: %s", manufacturer, description, serial);
       	curdev = curdev->next;
    }

    return true;
}

// Initialize the Infinite Noise Multiplier USB interface.
bool initializeUSB(struct ftdi_context *ftdic, char **message, char *serial) {
    ftdi_init(ftdic);
    struct ftdi_device_list *devlist;

    // search devices
    int rc = 0;
    if ((rc = ftdi_usb_find_all(ftdic, &devlist, INFNOISE_VENDOR_ID, INFNOISE_PRODUCT_ID)) < 0) {
        *message = "Can't find Infinite Noise Multiplier";
        return false;
    }

    // only one found, or no serial given
    if (rc >= 0) {
	if (serial == NULL) {
            // more than one found AND no serial given
            if (rc >= 2) {
		*message = "Multiple Infnoise TRNGs found and serial not specified, using the first one!";
            }
            if (ftdi_usb_open(ftdic, INFNOISE_VENDOR_ID, INFNOISE_PRODUCT_ID) < 0) {
                if(!isSuperUser()) {
                    *message = "Can't open Infinite Noise Multiplier. Try running as super user?";
                } else {
                    *message = "Can't open Infinite Noise Multiplier";
                }
                return false;
	    }
        } else {
            // serial specified
            rc = ftdi_usb_open_desc(ftdic, INFNOISE_VENDOR_ID, INFNOISE_PRODUCT_ID, NULL, serial);
            if (rc < 0) {
                if(!isSuperUser()) {
                    *message = "Can't find Infinite Noise Multiplier. Try running as super user?";
                } else {
                    *message = "Can't find Infinite Noise Multiplier with given serial";
                }
                return false;
	    }
        }
    }

    // Set high baud rate
    rc = ftdi_set_baudrate(ftdic, 30000);
    if(rc == -1) {
        *message = "Invalid baud rate";
        return false;
    } else if(rc == -2) {
        *message = "Setting baud rate failed";
        return false;
    } else if(rc == -3) {
        *message = "Infinite Noise Multiplier unavailable";
        return false;
    }
    rc = ftdi_set_bitmode(ftdic, MASK, BITMODE_SYNCBB);
    if(rc == -1) {
        *message = "Can't enable bit-bang mode";
        return false;
    } else if(rc == -2) {
        *message = "Infinite Noise Multiplier unavailable\n";
        return false;
    }

    // Just test to see that we can write and read.
    uint8_t buf[64u] = {0u,};
    if(ftdi_write_data(ftdic, buf, 64) != 64) {
        *message = "USB write failed";
        return false;
    }
    if(ftdi_read_data(ftdic, buf, 64) != 64) {
        *message = "USB read failed";
        return false;
    }
    return true;
}

uint32_t readRawData(struct ftdi_context *ftdic, uint8_t *result, char **message, bool *errorFlag) {
    return readData_private(ftdic, result, message, errorFlag, false, true, 0, false);
}

uint32_t readData(struct ftdi_context *ftdic, uint8_t *result, char **message, bool *errorFlag, uint32_t outputLength) {
    return readData_private(ftdic, result, message, errorFlag, false, false, outputLength, false);
}

uint32_t readData_private(struct ftdi_context *ftdic, uint8_t *result, char **message, bool *errorFlag,
                        bool noOutput, bool raw, uint32_t outputLength, bool devRandom) {
    uint8_t inBuf[BUFLEN];
    struct timespec start;
    clock_gettime(CLOCK_REALTIME, &start);

    // write clock signal
    if(ftdi_write_data(ftdic, outBuf, BUFLEN) != BUFLEN) {
        *message = "USB write failed";
        *errorFlag = true;
    }

    // and read 512 byte from the internal buffer (in synchronous bitbang mode)
    if(ftdi_read_data(ftdic, inBuf, BUFLEN) != BUFLEN) {
        *message = "USB read failed";
        *errorFlag = true;
    }

    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    uint32_t us = diffTime(&start, &end);
    if(us <= MAX_MICROSEC_FOR_SAMPLES) {
        uint8_t bytes[BUFLEN/8u];
        uint32_t entropy = extractBytes(bytes, inBuf, message, errorFlag);

	// call health check and process bytes if OK
        if (inmHealthCheckOkToUseData() && inmEntropyOnTarget(entropy, BUFLEN)) {
            uint32_t byteswritten = processBytes(bytes, result, entropy, raw, devRandom, outputLength, noOutput, message, errorFlag);
	    return byteswritten;
        }
    }
    return 0;
}

#ifdef LIB_EXAMPLE_PROGRAM
// example use of libinfnoise - with keccak
int main() {
    char *serial=NULL; // use any device, can be set to a specific serial

    // initialize USB
    struct ftdi_context ftdic;
    initInfnoise(&ftdic, serial);

    // parameters for readData(..):
    bool rawOutput = true;
    uint32_t multiplier = 10u;

    // calculate output size based on the parameters:
    // when using the multiplier, we need a result array of 32*MULTIPLIER - otherwise 64(BUFLEN/8) bytes
    uint32_t resultSize;
    if (multiplier == 0 || rawOutput == true) {
        resultSize = BUFLEN/8u;
    } else {
        resultSize = multiplier*32u;
    }

    uint64_t totalBytesWritten = 0u;

    // read and print in a loop
    while (totalBytesWritten < 100000) {
        uint8_t result[resultSize];
        uint64_t bytesWritten = 0u;
        bytesWritten = readData(&ftdic, keccakState, result, multiplier);

	// check for -1, indicating an error
        totalBytesWritten += bytesWritten;

	// make sure to only read as many bytes as readData returned. Only those have passed the health check in this round (usually all)
        fwrite(result, 1, bytesWritten, stdout);
    }
}
#endif
