/*
 * commands.c
 *
 *  Created on: Apr 2, 2019
 *      Author: Austin
 */

#include <string.h>
#include <stdlib.h>

#include "application_properties.h"
#include "native_gecko.h"

#include "b64.h"

#include "commands.h"
#include "ignition.h"
#include "crypto.h"

#include "assert.h"

static const char *ERROR = "ERROR", *OK = "OK";
static char buf[1280];
STATIC_ASSERT(sizeof(buf) > 4+(sizeof(struct Status)*4)/3, "buf[] should be able to contain a base64 encoded struct Status");

#define NARGS(x) if(argc!=x){debug("ERROR: expected %d args, got %d\n",x,argc);return ERROR;}
#define NEED_FULL() if(key_config[conn_info[conn].keyid].limited){debug("ERROR: limited key (%d)\n", conn_info[conn].keyid);return ERROR;}
#define ADD_TO_BUF(...) nbytes += snprintf(buf+nbytes, sizeof(buf)-nbytes, __VA_ARGS__)

int handle_command(char *fullcmd, uint8_t connection){
	char *codeStr, **argv;
	const uint8_t keyid = conn_info[connection].keyid;
	const struct KeyConfig *keys = &key_config[keyid];
	int nargs = 0;

	debug("command: \"%s\"\n", fullcmd);

	for(int i=strlen(fullcmd);i>=0;i--)
		nargs += fullcmd[i] == ':';
	//nargs -= 1;		// first part isnt included

	if(nargs < 0){
		debug("misformed command: \"%s\"\n", fullcmd);
		gecko_cmd_le_connection_close(connection);
		free(fullcmd);
		return 1;
	}

	debug("%d args\n", nargs);

	codeStr = strtok(fullcmd, ":");
	argv = malloc(sizeof(char*) * nargs);
	for(int i=0;i<nargs;i++)
		argv[i] = strtok(0, ":");

	if(argv[0][0] != 'a'){
		const uint8_t code = atoi(codeStr), next_code = key_config[keyid].next_code;
		if(code == next_code){
			debug("valid code! (%d)\n", code);
		}
		else{
			debug("invalid command code!\n");
			debug("keyid = %d\nlast_code = %d; new_code = %d\n", keyid, next_code, code);
			gecko_cmd_le_connection_close(connection);
			free(fullcmd);
			return 1;
		}
	}

	if(strlen(argv[0]) > 1){
		debug("ERROR: invalid command length (%d)\n", strlen(argv[0]));
		return 1;
	}

	debug("got command: \"%c\"\n", argv[0][0]);
	/*debug("%d args:\n", nargs);
	for(int i=0;i<nargs;i++)
		debug("%d: %s\n",i,argv[i]);*/

	const char *resp = 0;
	switch(argv[0][0]){
	case 'a':	// AUTH
		resp = auth(connection, nargs, argv);
		break;
	case 'r':	// REG
		resp = reg(connection, nargs, argv);
		break;
	case 'u':	// UNREG
		resp = unreg(connection, nargs, argv);
		break;
	case 'n':	// ON
		debug("turning on\n");
		resp = set_ignition(connection, nargs, argv);
		break;
	case 'f':	// OFF
		debug("turning off\n");
		resp = set_ignition(connection, nargs, argv);
		break;
	case 'g':	// GET
		debug("got GET request\n");
		resp = get(connection, nargs, argv);
		break;
	case 'p':	// UPDATE
		start_update(connection, nargs, argv);
		goto cleanup;
	default:
		debug("got unexpected command (%c)\n", argv[0][0]);
		gecko_cmd_le_connection_close(connection);
		goto cleanup;
	}

	send_response(keyid, keys, resp, connection);

cleanup:
	free(fullcmd);

	return 0;
}

const char *auth(uint8_t conn, int argc, char **argv){
	debug("got auth cmd\n");

	conn_info[conn].authenticated = 1;
	conn_info[conn].keyid = argc;

	int nbytes = 0;
	ADD_TO_BUF("OK:{\"state\":%d,\"ver\":[%d,%d]}",status.on,
			APP_PROPERTIES_VERSION_MAJOR, APP_PROPERTIES_VERSION_MINOR);

	return buf;
}

// register a new key
// arg 1: 'f' or 'l', for full or limited keys
// arg 2: base64 encoded AES and HMAC keys
const char *reg(uint8_t conn, int argc, char **argv){
	NARGS(5);
	NEED_FULL();

	if(strlen(argv[1]) != 1)
		return ERROR;

	if(argv[1][0] != 'f' && argv[1][0] != 'l')
		return ERROR;

	debug("registering keys\n");

	//rejoin keystring:
	argv[3][-1] = ':';

	struct KeyConfig newkey = { .limited = argv[1][0] == 'l' };
	if(decode_keys(&newkey, argv[2]))	// TODO: check for errors
		return ERROR;

	const char *idstr = save_keys(&newkey);
	const int id = atoi(idstr);

	// TODO: figure out a good max length for key names, truncate if too long
	if(strlen(argv[4]) >= 64)
		argv[4][64] = 0;

	struct gecko_msg_flash_ps_save_rsp_t *res = gecko_cmd_flash_ps_save(PS_KEY_NAME(id), strlen(argv[4])+1, argv[4]);
	if(res->result)
		return ERROR;

	return idstr;
}

// unregister a key
// arg 1: key id to unregister
const char *unreg(uint8_t conn, int argc, char **argv){
	NARGS(2);
	NEED_FULL();

	// TODO: access controls

	int keyid = atoi(argv[1]);

	if(keyid == 0){
		debug("ERROR: trying to delete key 0\n");
		return ERROR;
	}

	debug("unregistering keys: %d\n", keyid);

	return del_keys(keyid)?OK:ERROR;
}

// turn ignition switch on or off
// no args (the command, argv[0], determines if the switch is turned on or off)
const char *set_ignition(uint8_t conn, int argc, char **argv){
	static const char denied[] = "DENIED";

	NARGS(1);

	// TODO: notify all other connected devices that the ignition has been switched

	if(check_rules(conn_info[conn].keyid, 1, 1))
		return denied;

	const uint8_t on = (argv[0][0] == 'n'),
			pin_value = on?IGN_GPIO_ON:IGN_GPIO_OFF;

	GPIO_PortOutSetVal(IGN_GPIO_PORT, pin_value<<IGN_GPIO_PIN, 1<<IGN_GPIO_PIN);

	status.on = on;

	return OK;
}

const char *get_time(uint8_t conn, int argc, char **argv){
	NARGS(1);
	sprintf(buf, "OK:%lld", get_local_time());
	return buf;
}

const char *set_time(uint8_t conn, int argc, char **argv){
	NARGS(2);
	NEED_FULL();

	time_t now = atoll(argv[1]);
	if(now == 0)
		return ERROR;

	set_time_offset(now);
	return OK;
}

const char *create_rule(uint8_t conn, int argc, char **argv){
	NARGS(1);
	NEED_FULL();
	return OK;
}

// return info about the ignition
const char *get(uint8_t conn, int argc, char **argv){
	NEED_FULL();

	switch(argv[1][0]){
	case 'm': {		// main config info
		NARGS(2);
		int nbytes = 0;
		ADD_TO_BUF("{\"registeredKeys\":[");
		for(int i=0;i<MAX_KEYS;i++)
			if(get_registered_key(i))
				ADD_TO_BUF("%d,", i);
		nbytes--;
		ADD_TO_BUF("]}");
		return buf;
	}
	case 'k': {		// return key info
		NARGS(3);
		int id = atoi(argv[2]);
		if(id <= 0 || id >= MAX_KEYS)
			return ERROR;
		struct gecko_msg_flash_ps_load_rsp_t *res = gecko_cmd_flash_ps_load(PS_KEY_NAME(id));
		if(res->result)
			return ERROR;
		snprintf(buf, sizeof(buf), "{\"name\":\"%s\",\"limited\":%c,\"rules\":[]}",res->value.data, key_config[id].limited?'1':'0');
		return buf;
	}
	default:
		debug("ERROR: invalid sub command for get\n");
		return ERROR;
	}
}

const char *start_update(uint8_t conn, int argc, char **argv){
	NEED_FULL();
	NARGS(1);
// set boot_to_ota and close the connection so the device will reset
// when it gets the connection_closed event
  status.boot_to_ota = true;
  gecko_cmd_le_connection_close(conn);
  return "";
}
