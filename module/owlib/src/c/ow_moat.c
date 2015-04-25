/*
$Id$
    OWFS -- One-Wire filesystem
    Written 2015 by Matthias Urlichs
	email: <matthias@urlichs.de>
	Released under the GPL
	See the header file: ow.h for full attribution
	1wire/iButton system from Dallas Semiconductor
*/

/* 
    This code is a generic controller for the "MoaT" family of devices,
    which is miplemented as slave code on AVR Atmega and similar devices.

    These devices are not generic, but can be interrogates as to the
    features they contain.
*/

#include <config.h>
#include "owfs_config.h"
#include "ow_moat.h"

/* ------- Prototypes ----------- */

READ_FUNCTION(FS_r_info_raw);
READ_FUNCTION(FS_r_name);
READ_FUNCTION(FS_r_console);
READ_FUNCTION(FS_r_port_raw);
READ_FUNCTION(FS_r_ports_raw);
WRITE_FUNCTION(FS_w_console);
WRITE_FUNCTION(FS_w_port_raw);

static GOOD_OR_BAD OW_r_std(BYTE *buf, size_t *buflen, BYTE type, BYTE stype, const struct parsedname *pn);
static GOOD_OR_BAD OW_w_std(BYTE *buf, size_t size,    BYTE type, BYTE stype, const struct parsedname *pn);
//WRITE_FUNCTION(FS_w_raw);
//READ_FUNCTION(FS_r_status);
//WRITE_FUNCTION(FS_w_status);
//READ_FUNCTION(FS_r_mem);
//WRITE_FUNCTION(FS_w_mem);

#define _1W_READ_MOAT          0xF2
#define _1W_WRITE_MOAT         0xF4

/* ------- Structures ----------- */

static struct aggregate infotypes = { CFG_MAX, ag_numbers, ag_separate, };

static struct filetype MOAT[] = {
	F_STANDARD,
	{"config", PROPERTY_LENGTH_SUBDIR, NON_AGGREGATE, ft_subdir, fc_subdir, NO_READ_FUNCTION, NO_WRITE_FUNCTION, VISIBLE, NO_FILETYPE_DATA, },
	{"config/raw", 255, &infotypes, ft_binary, fc_static, FS_r_info_raw, NO_WRITE_FUNCTION, VISIBLE, NO_FILETYPE_DATA, },
	{"config/name", 255, NON_AGGREGATE, ft_vascii, fc_static, FS_r_name, NO_WRITE_FUNCTION, VISIBLE, NO_FILETYPE_DATA, },
	{"console", 255, NON_AGGREGATE, ft_vascii, fc_static, FS_r_console, FS_w_console, VISIBLE, NO_FILETYPE_DATA, },
	{"config/port", 255, &infotypes, ft_binary, fc_static, FS_r_port_raw, FS_w_port_raw, VISIBLE, NO_FILETYPE_DATA, },
	{"config/ports", 255, NON_AGGREGATE, ft_binary, fc_static, FS_r_ports_raw, NO_WRITE_FUNCTION, VISIBLE, NO_FILETYPE_DATA, },

};

DeviceEntryExtended(F0, MOAT, DEV_alarm, NO_GENERIC_READ, NO_GENERIC_WRITE);

/* ------- Functions ------------ */

static ZERO_OR_ERROR FS_r_info_raw(struct one_wire_query *owq)
{
    BYTE buf[256];
    size_t len = OWQ_size(owq);
	if(len>sizeof(buf)) len=sizeof(buf);

	RETURN_ERROR_IF_BAD( OW_r_std(buf,&len, M_CONFIG, OWQ_pn(owq).extension, PN(owq)));

    return OWQ_format_output_offset_and_size((const char *)buf, len, owq);
}

static ZERO_OR_ERROR FS_r_port_raw(struct one_wire_query *owq)
{
    BYTE buf[1];
    size_t len = OWQ_size(owq);
	if(len>sizeof(buf)) len=sizeof(buf);

	RETURN_ERROR_IF_BAD( OW_r_std(buf,&len, M_PORT, OWQ_pn(owq).extension, PN(owq)));

    return OWQ_format_output_offset_and_size((const char *)buf, len, owq);
}

static ZERO_OR_ERROR FS_r_ports_raw(struct one_wire_query *owq)
{
    BYTE buf[10];
    size_t len = OWQ_size(owq);
	if(len>sizeof(buf)) len=sizeof(buf);

	RETURN_ERROR_IF_BAD( OW_r_std(buf,&len, M_PORT, 0, PN(owq)));

    return OWQ_format_output_offset_and_size((const char *)buf, len, owq);
}

static ZERO_OR_ERROR FS_r_name(struct one_wire_query *owq)
{
    BYTE buf[256];
    size_t len = OWQ_size(owq);

	RETURN_ERROR_IF_BAD( OW_r_std(buf,&len, M_CONFIG, CFG_NAME, PN(owq)));

    return OWQ_format_output_offset_and_size((const char *)buf, len, owq);
}

static ZERO_OR_ERROR FS_r_console(struct one_wire_query *owq)
{
    BYTE buf[256];
    size_t len = OWQ_size(owq);

	RETURN_ERROR_IF_BAD( OW_r_std(buf,&len, M_CONSOLE, 1, PN(owq)));

    return OWQ_format_output_offset_and_size((const char *)buf, len, owq);
}

static ZERO_OR_ERROR FS_w_console(struct one_wire_query *owq)
{
	if (OWQ_offset(owq) != 0)
		return -EINVAL; /* ignore? */
	return GB_to_Z_OR_E( OW_w_std( (BYTE *) OWQ_buffer(owq), OWQ_size(owq), M_CONSOLE,1, PN(owq)) ) ;
}

static ZERO_OR_ERROR FS_w_port_raw(struct one_wire_query *owq)
{
	BYTE *buf = (BYTE *) OWQ_buffer(owq);
    size_t len = OWQ_size(owq);
	if (OWQ_offset(owq) != 0)
		return -EINVAL; /* ignore? */

	// Hack for testing, otherwise we'll not be able to clear a port using owwrite.
	if(len == 1 && (*buf == '0' || *buf == '1')) {
		*buf -= '0';
	}

	return GB_to_Z_OR_E( OW_w_std( buf,len, M_PORT,OWQ_pn(owq).extension, PN(owq)) ) ;
}

static GOOD_OR_BAD OW_r_std(BYTE *buf, size_t *buflen, BYTE type, BYTE stype, const struct parsedname *pn)
{
	BYTE p[3] = { _1W_READ_MOAT, type,stype };

    size_t maxlen = *buflen;
    BYTE len;
	GOOD_OR_BAD ret = gbGOOD;

	struct transaction_log tfirst[] = {
		TRXN_START,
		TRXN_WRITE3(p),
		TRXN_READ1(&len),
		TRXN_END,
	};
	if (maxlen == 0) {
		return gbGOOD;
	}

	LEVEL_DEBUG( "read: read len for %d %d",type,stype) ;
	/* 0xFF means the device was too slow */
	if ( BAD(BUS_transaction(tfirst, pn)) || len == 0xFF) {
		goto out_bad;
	}
	LEVEL_DEBUG( "read: got len %d",len) ;
	if (len > maxlen) {
		/* don't read all and don't bother with CRC.
		 * This will abort the read on the client side so that
		 * there'll be no side effects like marked-as-sent buffers
		 * or cleared 'conditional search' flags */
		struct transaction_log tinfo[] = {
			TRXN_READ(buf,maxlen),
			TRXN_END,
		};

		if ( BAD(BUS_transaction(tinfo, pn)) ) {
			goto out_bad;
		}
	} else {
		UINT crc;
		BYTE crcbuf[2];
		struct transaction_log recv_buf[] = {
			TRXN_READ(buf,len),
			TRXN_READ2(crcbuf),
			TRXN_END,
		};
		struct transaction_log recv_crc[] = {
			TRXN_READ2(crcbuf),
			TRXN_END,
		};
		struct transaction_log xmit_crc[] = {
			TRXN_WRITE2(crcbuf),
			TRXN_END,
		};

		if ( BAD(BUS_transaction(len ? recv_buf : recv_crc, pn)) ) {
			goto out_bad;
		}

		crc = CRC16compute(p,3,0);
		crc = CRC16compute(&len,1,crc);
		if (len) crc = CRC16compute(buf,len,crc);
		LEVEL_DEBUG( "read CRC: GOOD, got %02x%02x",crcbuf[0],crcbuf[1]) ;
		if ( CRC16seeded (crcbuf,2,crc) ) {
			LEVEL_DEBUG("CRC error");
			goto out_bad;
		}
		crcbuf[0] = ~crcbuf[0];
		crcbuf[1] = ~crcbuf[1];
		if ( BAD(BUS_transaction(xmit_crc, pn)) ) {
			goto out_bad;
		}
		*buflen = len;
	}

	LEVEL_DEBUG( "read: GOOD, got %d",*buflen) ;
	return ret;
out_bad:
	return gbBAD;
}

static GOOD_OR_BAD OW_w_std(BYTE *buf, size_t size, BYTE type, BYTE stype, const struct parsedname *pn)
{
	BYTE p[4] = { _1W_WRITE_MOAT, type,stype, size};
	BYTE crcbuf[2];
	UINT crc;

	struct transaction_log tfirst[] = {
		TRXN_START,
		TRXN_WRITE(p,4),
		TRXN_WRITE(buf,size),
		TRXN_READ2(crcbuf),
		TRXN_END,
	};
	struct transaction_log xmit_crc[] = {
		TRXN_WRITE2(crcbuf),
		TRXN_END,
	};

	if (size == 0) {
		return gbGOOD;
	}
	if (size > 255) {
		return gbBAD;
	}

	LEVEL_DEBUG( "write: %d for %d %d",size,type,stype) ;
	
	if ( BAD(BUS_transaction(tfirst, pn))) {
		goto out_bad;
	}

	crc = CRC16compute(p,4,0);
	crc = CRC16compute(buf,size,crc);
	if ( CRC16seeded (crcbuf,2,crc) ) {
		LEVEL_DEBUG("CRC error");
		goto out_bad;
	}
	LEVEL_DEBUG( "read CRC: GOOD, got %02x%02x",crcbuf[0],crcbuf[1]) ;
	crcbuf[0] = ~crcbuf[0];
	crcbuf[1] = ~crcbuf[1];
	if ( BAD(BUS_transaction(xmit_crc, pn)) ) {
		goto out_bad;
	}
	return gbGOOD;
out_bad:
	return gbBAD;
}

#if 0
static ZERO_OR_ERROR FS_w_mem(struct one_wire_query *owq)
{
	return COMMON_write_eprom_mem_owq(owq) ;
}

static ZERO_OR_ERROR FS_w_status(struct one_wire_query *owq)
{
	return GB_to_Z_OR_E(OW_w_status(OWQ_explode(owq))) ;
}

static ZERO_OR_ERROR FS_w_page(struct one_wire_query *owq)
{
	size_t pagesize = 32;
	return COMMON_offset_process( FS_w_mem, owq, OWQ_pn(owq).extension * pagesize) ;
}

static GOOD_OR_BAD OW_w_status(BYTE * data, size_t size, off_t offset, struct parsedname *pn)
{
	BYTE p[6] = { _1W_WRITE_STATUS, LOW_HIGH_ADDRESS(offset), data[0] };
	GOOD_OR_BAD ret = gbGOOD;
	struct transaction_log tfirst[] = {
		TRXN_START,
		TRXN_WR_CRC16(p, 4, 0),
		TRXN_PROGRAM,
		TRXN_READ1(p),
		TRXN_END,
	};

	if (size == 0) {
		return gbGOOD;
	}
	if (size == 1) {
		return BUS_transaction(tfirst, pn) || (p[0] & (~data[0]));
	}
	BUSLOCK(pn);
	if ( BAD(BUS_transaction(tfirst, pn)) || (p[0] & ~data[0])) {
		ret = gbBAD;
	} else {
		size_t i;
		const BYTE *d = &data[1];
		UINT s = offset + 1;
		struct transaction_log trest[] = {
			//TRXN_WR_CRC16_SEEDED( p, &s, 1, 0 ) ,
			TRXN_WR_CRC16_SEEDED(p, p, 1, 0),
			TRXN_PROGRAM,
			TRXN_READ1(p),
			TRXN_END,
		};
		for (i = 0; i < size; ++i, ++d, ++s) {
			if ( BAD(BUS_transaction(trest, pn)) || (p[0] & ~d[0])) {
				ret = gbBAD;
				break;
			}
		}
	}
	BUSUNLOCK(pn);
	return ret;
}
#endif

