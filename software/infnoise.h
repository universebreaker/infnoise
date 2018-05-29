#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <ftdi.h>

// Structure for parsed command line options
struct opt_struct {
	uint32_t outputLength; // We output all the entropy when outputLength == 0
	bool daemon;		// Run as daemon?
	bool debug;		// Print debugging info?
	bool devRandom;		// Feed /dev/random?
	bool noOutput;		// Supress output?
	bool listDevices;	// List possible USB-devices?
	bool help;		// Show help
	bool none;		// set to true when no valid arguments where detected
	bool raw;		// No whitening?
	bool version;		// Show version
	char *pidFileName;	// Name of optional PID-file
	char *serial;		// Name of selected device
};

void startDaemon(struct opt_struct *opts);
