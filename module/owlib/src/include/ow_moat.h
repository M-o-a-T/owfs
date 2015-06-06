/*
$Id$
    OWFS -- One-Wire filesystem
    OWHTTPD -- One-Wire Web Server
    Written 2003 Paul H Alfille
	email: paul.alfille@gmail.com
	Released under the GPL
	See the header file: ow.h for full attribution
	1wire/iButton system from Dallas Semiconductor

This file (c) 2015 Matthias Urlichs <matthias@urlichs.de>.

The MoaT, or Master of all Things, is configurable and versatile slave code
base don ATmega 88 (or better). You can find it at
git@github.com:M-o-a-T/owslave.git

The wire format for data transfer from and to MoaT devices is documented
there.
*/

#ifndef OW_MOAT_H
#define OW_MOAT_H

#ifndef OWFS_CONFIG_H
#error Please make sure owfs_config.h is included *before* this header file
#endif
#include "ow_standard.h"

/* ------- Structures ----------- */

DeviceHeader(MOAT);

/* --- data format --- */

#define _1W_READ_GENERIC          0xF2
#define _1W_WRITE_GENERIC         0xF4

/* --- Data Types --- */

typedef enum {
	M_CONFIG, // configuration data
	M_ALERT,  // conditional search
	M_STATUS, // some device status+statistics (reset, broken comms, CRC errors ...)
	M_CONSOLE,// debugging, commands, whatever
	M_PORT,   // binary input/output
	M_PWM,    // pulse-width modulated output (tied to output port)
	M_COUNT,  // hardware transition counter (tied to input port)
	M_ADC,    // analog input
	M_TEMP,   // temperature sensor
	M_HUMID,  // humidity sensor
	M_PID,    // basic parameterizable controller
	M_SMOKE,  // smoke detector
	M_MAX,
#define M_MAX M_MAX
} m_type;

#ifdef MOAT_NAMES
static const char *m_names[] = {
	"config",
	"alert",
	"status",
	"console",
	"port",
	"pwm",
	"count",
	"adc",
	"temp",
	"humid",
	"pid",
	"smoke",
	"_max"
};

#endif

typedef enum {
	CFG_LIST = 0, // list of known CFG_* entries (bitmap)
	CFG_NUMS,     // list of available M_* subdevices (M_MAX bytes)
	CFG_EUID,     // reserved for radio
	CFG_RF12,     // reserved for radio
	CFG_CRYPTO,   // reserved
	CFG_OWID,     // this device's 1wire ID
	CFG_TYPE,     // Device configuration data
	CFG_NAME,     // device name
	CFG_MAX,
#define CFG_MAX CFG_MAX
} cfg_type;

/* Status */
typedef enum {
    S_reboot,
    S_max
#define STATUS_MAX S_max
} t_status_nr;

#ifdef MOAT_NAMES
static const char *s_names[] = { /* status, starting with #1 */
	"reboot",
};
#endif

/* reason for reset */
typedef enum {
    S_boot_unknown,
    S_boot_powerup,
    S_boot_brownout,
    S_boot_watchdog,
    S_boot_external,
} t_status_boot;

#endif

