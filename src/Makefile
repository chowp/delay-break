# ap-monitor - Highly Optimized Radio Scanning Tool
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

NAME=delay-break
OBJS=hello.o 

CFLAGS+=-Wall -DDO_DEBUG=$(DEBUG) -g -DPCAP

LIBS+=-lpcap -lpthread


buildstamp=.build_debug
all: $(buildstamp) $(NAME)
# include dependencies
hello.o:hello.c 

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	-rm -f *.o *~
	-rm -f $(NAME)
	-rm -f .build_*

$(buildstamp):
	make clean
	touch $@
