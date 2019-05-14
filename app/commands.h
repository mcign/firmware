/*
 * commands.h
 *
 *  Created on: Apr 2, 2019
 *      Author: Austin
 */

#ifndef COMMANDS_H_
#define COMMANDS_H_

#include <stdint.h>

#define CMD(name) const char *name(uint8_t conn, int argc, char **argv)

int handle_command(char *fullcmd, uint8_t connection);

// command handler definitions:
CMD(auth);
CMD(reg);
CMD(unreg);
CMD(set_ignition);
CMD(get_config);
CMD(set_config);
CMD(get_time);
CMD(set_time);
CMD(create_rule);
CMD(get);
CMD(start_update);

#endif /* COMMANDS_H_ */
