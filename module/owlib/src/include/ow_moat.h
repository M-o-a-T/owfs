/*
$Id$
    OWFS -- One-Wire filesystem
    OWHTTPD -- One-Wire Web Server
    Written 2003 Paul H Alfille
	email: paul.alfille@gmail.com
	Released under the GPL
	See the header file: ow.h for full attribution
	1wire/iButton system from Dallas Semiconductor
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
/*
    All data follow this scheme:

	write 1byte: data type
	write 1byte: channel no. -- if zero, concat data / availability mask / whatever
	read/write arbitrary data, as defined by data type
	read/write ~CRC16
	write/read ack: CRC16
*/

/* --- Data Types --- */

typedef enum {
	M_CONFIG, // configuration data
	M_ALERT,  // conditional search
	M_STATS,  // some device statistics (broken comms, CRC errors ...)
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
	"stats",
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
	CFG_TYPE,     // kkkk
	CFG_NAME,     // device name
	CFG_MAX,
#define CFG_MAX CFG_MAX
} cfg_type;

<<<<<<< moat
/*
    M_INFO: basic data about the device.
	Write: 1 byte: data type to get details for.
	Read (all): length of structure, type-specific bytes, 16bit CRC.
*/
=======
/* Status */
typedef enum {
    S_reboot,
    S_max
#define STATUS_MAX S_max
} t_status_nr;
>>>>>>> local

/*
	Data for M_INFO: send a byte with those bits set that correspond to a
	type in [t,t+7] which the device supports.
	For instance, one that has a thermometer would send 0x08.
	Then, for each bit that's set, send a byte that tells the master how
	many of these we support. So 0x08 0x02 means we have two thermometers
	and 0x18 0x02 0x01 has one additional hygrometer.
	t +=8, repeat until you told the master about everything you can do.
	Send 2 bytes of CRC.
*/

/*
	Data for M_CONFIG: as M_INFO, but send raw configuration entries.
	CFG_LIST sends a list of existing CFG_* types (one byte per entry).
	All entries are unique.
*/

/*
	Data for M_ALERT: Send a byte+extension with the bits set that
	correspond to a type for which the device supports alerting, i.e. it
	responds to CONDITIONAL_SEARCH.
	For example, a device that supports console notifications and humidity
	thresholds would send 0x11.
	Send 2 bytes of CRC.
*/

/*
    Data for M_CONSOLE: 
	For each console port, send a byte+extension with a feature bitmask.
	Send 2 bytes of CRC.
*/
#define M_CONSOLE_READ 0x01 /* data might be available */
#define M_CONSOLE_WRITE 0x02 /* the device understands text commands */
#define M_CONSOLE_ALERT 0x04 /* Alert condition when text is available */

/*
	Data for M_PORT:
	For each input, send a byte+extension with feature bits.
*/
#define M_INPUT_COUNT_LO 0x01 /* does the input count low>high transitions? */
#define M_INPUT_COUNT_HI 0x02 /* does the input count high>low transitions? */

/*
	Data for M_OUTPUT:
	For each output, send a byte+extension with feature bits.
*/
#define M_OUTPUT_TIMER 0x01 /* does the output support a timer? */

/*
	Data for M_ADC:
	For each analog input, send a byte+extension with feature bits.
*/
#define M_ADC_ALERT 0x01 /* does the ADC support alarm thresholds? */

/*
	Data for M_TEMP:
	For each sensor, send a byte+ext with feature bits.
*/
#define M_TEMP_MIN 0x01 /* supports a minimum threshold, alerting */
#define M_TEMP_MAX 0x02 /* supports a maximum threshold, alerting */

/*
	Data for M_HUMID:
	For each sensor, send a byte+ext with feature bits.
*/
#define M_HUMID_MIN 0x01 /* supports a minimum threshold, alerting */
#define M_HUMID_MAX 0x02 /* supports a maximum threshold, alerting */

/*
	Data for M_PID:
	For each PID loop, send a byte+ext with feature bits.
*/
#define M_PID_OUTPUT 0x01 /* can control a PWM (or whatever) on one of its outputs */
#define M_PID_INPUT 0x02 /* can read one of its inputs */

/* --- temparature sensors --- */

/*
	Data type: 16 bits (8+8) signed, integer part first, CRC16
*/

#endif

