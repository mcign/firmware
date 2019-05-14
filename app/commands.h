/*
    Copyright 2018,2019 Austin Haigh

    This file is part of MCIGN.

    MCIGN is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    MCIGN is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MCIGN.  If not, see <https://www.gnu.org/licenses/>.

*/


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
