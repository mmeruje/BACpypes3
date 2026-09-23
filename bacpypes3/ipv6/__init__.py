"""
IPv6
"""

import asyncio
import socket
import struct
import functools

from typing import Any, Callable, List, Tuple, Optional, Union, cast

from ..debugging import ModuleLogger, bacpypes_debugging

from ..comm import Server
from ..pdu import LocalBroadcast, IPv6Address, IPv6LinkLocalMulticastAddress, PDU

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# move this to settings sometime
BACPYPES_ENDPOINT_RETRY_INTERVAL = 1.0


@bacpypes_debugging
class IPv6DatagramProtocol(asyncio.DatagramProtocol):
    _debug: Callable[..., None]

    server: "IPv6DatagramServer"
    destination: Union[IPv6Address, LocalBroadcast, None]

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if _debug:
            IPv6DatagramProtocol._debug("connection_made %r", transport)

        # get the 'name' of the socket when it was bound which is useful
        # for ephemeral sockets used by applications running as a foreign device
        socket = transport.get_extra_info("socket")
        if _debug:
            IPv6DatagramProtocol._debug("    - socket: %r", socket)
        if socket is not None:
            socket_name = socket.getsockname()
            if _debug:
                IPv6DatagramProtocol._debug("    - socket_name: %r", socket_name)
            self.destination = cast(IPv6Address, IPv6Address(socket_name))
        else:
            self.destination = None

    def datagram_received(self, data: bytes, addr: Tuple[Any, ...]) -> None:
        if _debug:
            IPv6DatagramProtocol._debug("datagram_received %r %r", data, addr)

        pdu = PDU(data, source=IPv6Address(addr), destination=self.destination)
        asyncio.ensure_future(self.server.confirmation(pdu))

    def error_received(self, exc: Exception) -> None:
        if _debug:
            IPv6DatagramProtocol._debug("error_received %r", exc)
        if self.server:
            self.server._protocol_error(exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if _debug:
            IPv6DatagramProtocol._debug("connection_lost %r", exc)
        if exc and self.server:
            self.server._protocol_error(exc)


@bacpypes_debugging
class IPv6DatagramServer(Server[PDU]):
    _debug: Callable[..., None]
    _exception: Callable[..., None]
    _transport_tasks: List[Any]
    _local_transport_ready: asyncio.Event

    interface_index: int
    local_address: Tuple[str, int, int, int]
    local_address_no_scope: Tuple[str, int, int]
    broadcast_address: Tuple[str, int, int, int]
    multicast_groups: List[str]
    interface_name: Optional[str]
    transport: Optional[asyncio.DatagramTransport]
    protocol: Optional[IPv6DatagramProtocol]
    multicast_transport: Optional[asyncio.DatagramTransport]
    multicast_protocol: Optional[IPv6DatagramProtocol]

    def __init__(
        self,
        address: IPv6Address,
        multicast_groups: Optional[List[str]] = None,
        interface_name: Optional[str] = None,
    ) -> None:
        if _debug:
            IPv6DatagramServer._debug(
                "__init__ %r %r %r", address, multicast_groups, interface_name
            )

        # save the local address to check for reflections
        self.local_address = address.addrTuple
        if _debug:
            IPv6DatagramServer._debug("    - local_address: %r", self.local_address)

        # save the address without the scope/index so it can be rebound later
        self.local_address_no_scope = cast(Tuple[str, int, int], address.addrTuple[:3])
        if _debug:
            IPv6DatagramServer._debug(
                "    - local_address_no_scope: %r", self.local_address_no_scope
            )

        # initialized in set_local_transport_protocol callback
        self.transport = None
        self.protocol = None

        # initialized in set_multicast_transport_protocol callback
        self.multicast_transport = None
        self.multicast_protocol = None

        # the address tuple contains the interface index as the last element,
        # like ('::', 47808, 0, 0) for any interface, or if attempting to bind
        # to a specific interface, the result of socket.if_nametoindex()
        self.interface_index = address.addrTuple[-1]
        if _debug:
            IPv6DatagramServer._debug("    - interface_index: %r", self.interface_index)

        # if an interface name was provided, keep it so we can resolve the
        # (possibly changed) index when the interface comes back
        self.interface_name = interface_name
        if _debug:
            IPv6DatagramServer._debug("    - interface_name: %r", self.interface_name)

        # join the IANA assigned link-local multicast group
        if multicast_groups is None:
            multicast_groups = ["ff02::bac0"]
        self.multicast_groups = multicast_groups
        if _debug:
            IPv6DatagramServer._debug(
                "    - multicast_groups: %r", self.multicast_groups
            )

        # a lock so only one rebuild happens at a time
        self._rebuild_lock = asyncio.Lock()

        self._start_transports()

    def _make_local_socket(self, interface_index: int) -> socket.socket:
        """Create and bind a local (unicast) socket for the given interface."""
        # create a local socket
        local_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        if _debug:
            IPv6DatagramServer._debug("    - local_socket: %r", local_socket)

        # allow multiple applications to use the same port
        local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # set the hop limit to 255 for multicast and 64 for unicast to ensure routing
        local_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 64)
        local_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)

        # disable multicast loopback
        local_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

        # set the multicast interface
        if interface_index:
            local_socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index
            )

        # bind to the specific address to force the source address
        self.local_address = self.local_address_no_scope + (interface_index,)
        if _debug:
            IPv6DatagramServer._debug(
                "    - binding local_address: %r", self.local_address
            )
        local_socket.bind(self.local_address)

        return local_socket

    def _make_multicast_socket(self, interface_index: int) -> socket.socket:
        """Create and bind a separate multicast socket for the given interface."""
        multicast_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        if _debug:
            IPv6DatagramServer._debug("    - multicast_socket: %r", multicast_socket)

        # make socket ipv6 only, leaving port free for ipv4 applications
        multicast_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        # allow multiple applications to use the same port
        multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # join the groups
        for group in self.multicast_groups:
            if _debug:
                IPv6DatagramServer._debug("    - join group: %r", group)
            multicast_socket.setsockopt(
                socket.IPPROTO_IPV6,
                socket.IPV6_JOIN_GROUP,
                struct.pack(
                    "16sI",
                    socket.inet_pton(socket.AF_INET6, group),
                    interface_index,
                ),
            )

        # disable multicast loopback
        multicast_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

        # set the multicast interface so transmission stays on this link
        if interface_index:
            multicast_socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index
            )

        # bind to the wildcard address to receive multicast
        multicast_socket.bind(("", self.local_address_no_scope[1], 0, interface_index))

        return multicast_socket

    def _start_transports(self) -> None:
        """Create the local and multicast sockets and the datagram endpoints."""
        if _debug:
            IPv6DatagramServer._debug("_start_transports")

        # grab the loop to create tasks and endpoints
        loop: asyncio.events.AbstractEventLoop = asyncio.get_running_loop()

        # create a local socket
        local_socket = self._make_local_socket(self.interface_index)

        # easy call to create a local endpoint
        local_endpoint_task = loop.create_task(
            self.retrying_create_datagram_endpoint(loop, local_socket)
        )
        if _debug:
            IPv6DatagramServer._debug(
                "    - local_endpoint_task: %r", local_endpoint_task
            )
        local_endpoint_task.add_done_callback(
            functools.partial(self.set_local_transport_protocol, local_socket)
        )

        # keep a list of things that need to complete before sending stuff
        self._transport_tasks = [local_endpoint_task]
        self._local_transport_ready = asyncio.Event()

        # the first one is the broadcast address
        self.broadcast_address = cast(
            IPv6Address,
            IPv6Address(
                self.multicast_groups[0],
                port=self.local_address[1],
                interface=self.interface_index,
            ),
        ).addrTuple

        # if we are bound to the wildcard address, we can join the groups on the same socket
        if self.local_address[0] in ("::", "0:0:0:0:0:0:0:0"):
            for group in self.multicast_groups:
                if _debug:
                    IPv6DatagramServer._debug("    - join group: %r", group)
                local_socket.setsockopt(
                    socket.IPPROTO_IPV6,
                    socket.IPV6_JOIN_GROUP,
                    struct.pack(
                        "16sI",
                        socket.inet_pton(socket.AF_INET6, group),
                        self.interface_index,
                    ),
                )
        else:
            # create a separate socket for multicast
            multicast_socket = self._make_multicast_socket(self.interface_index)

            # create the multicast endpoint
            multicast_endpoint_task = loop.create_task(
                self.retrying_create_datagram_endpoint(loop, multicast_socket)
            )
            if _debug:
                IPv6DatagramServer._debug(
                    "    - multicast_endpoint_task: %r", multicast_endpoint_task
                )
            multicast_endpoint_task.add_done_callback(
                functools.partial(self.set_multicast_transport_protocol, multicast_socket)
            )
            self._transport_tasks.append(multicast_endpoint_task)

    async def retrying_create_datagram_endpoint(
        self, loop: asyncio.events.AbstractEventLoop, local_socket: socket.socket
    ):
        while True:
            try:
                return await loop.create_datagram_endpoint(
                    IPv6DatagramProtocol,
                    sock=local_socket,
                )
            except OSError:
                if _debug:
                    IPv6DatagramServer._debug(
                        "    - Could not create datagram endpoint, retrying..."
                    )
                await asyncio.sleep(BACPYPES_ENDPOINT_RETRY_INTERVAL)

    def set_local_transport_protocol(self, local_socket: socket.socket, task: asyncio.Task) -> None:
        if _debug:
            IPv6DatagramServer._debug(
                "set_local_transport_protocol %r, %r", local_socket, task
            )

        # get the results of creating the datagram endpoint
        transport, protocol = task.result()
        if _debug:
            IPv6DatagramServer._debug(
                "    - transport, protocol: %r, %r", transport, protocol
            )

        # make these the correct type
        self.transport = cast(asyncio.DatagramTransport, transport)
        self.protocol = cast(IPv6DatagramProtocol, protocol)

        # tell the protocol instance created that it should talk back to us
        self.protocol.server = self

        # ready now
        self._local_transport_ready.set()

    def set_multicast_transport_protocol(self, multicast_socket: socket.socket, task: asyncio.Task) -> None:
        if _debug:
            IPv6DatagramServer._debug(
                "set_multicast_transport_protocol %r, %r", multicast_socket, task
            )

        # get the results of creating the datagram endpoint
        transport, protocol = task.result()
        if _debug:
            IPv6DatagramServer._debug(
                "    - transport, protocol: %r, %r", transport, protocol
            )

        # make these the correct type
        self.multicast_transport = cast(asyncio.DatagramTransport, transport)
        self.multicast_protocol = cast(IPv6DatagramProtocol, protocol)

        # tell the protocol instance created that it should talk back to us
        self.multicast_protocol.server = self

        # incoming packets on this transport were sent as a local broadcast
        self.multicast_protocol.destination = cast(LocalBroadcast, LocalBroadcast())

    def _protocol_error(self, exc: Exception) -> None:
        """Called by the protocol when the socket raises or is lost; try to recover."""
        if _debug:
            IPv6DatagramServer._debug("_protocol_error %r", exc)

        # if we don't know an interface name we can't re-resolve the index
        if not self.interface_name:
            return

        asyncio.create_task(self._rebuild())

    async def _rebuild(self) -> None:
        """Close the current transports and bring the interface back up."""
        if _debug:
            IPv6DatagramServer._debug("_rebuild")
        async with self._rebuild_lock:
            if _debug:
                IPv6DatagramServer._debug("    - rebuilding transports")

            # close the old transports (if any)
            if self.transport:
                self.transport.close()
            if self.multicast_transport:
                self.multicast_transport.close()
            self.transport = None
            self.protocol = None
            self.multicast_transport = None
            self.multicast_protocol = None

            # clear the ready flag while rebuilding
            if hasattr(self, "_local_transport_ready"):
                self._local_transport_ready.clear()

            # try to get the current index from the interface name; this changes
            # when an interface goes away and comes back (e.g. 55 -> 56)
            try:
                new_index = socket.if_nametoindex(self.interface_name)
            except OSError:
                if _debug:
                    IPv6DatagramServer._debug(
                        "    - interface still gone, retrying later"
                    )
                # schedule a retry
                loop = asyncio.get_running_loop()
                loop.call_later(
                    BACPYPES_ENDPOINT_RETRY_INTERVAL,
                    lambda: asyncio.create_task(self._rebuild()),
                )
                return

            self.interface_index = new_index
            if _debug:
                IPv6DatagramServer._debug(
                    "    - new interface_index: %r", self.interface_index
                )

            # bring the transports back up with the new interface; if the bind
            # still fails (e.g. the address isn't back yet), retry later
            try:
                self._start_transports()
            except OSError as err:
                if _debug:
                    IPv6DatagramServer._debug(
                        "    - could not restart transports: %r", err
                    )
                # schedule a retry
                loop = asyncio.get_running_loop()
                loop.call_later(
                    BACPYPES_ENDPOINT_RETRY_INTERVAL,
                    lambda: asyncio.create_task(self._rebuild()),
                )

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            IPv6DatagramServer._debug("indication %r", pdu)

        # wait for set_local_transport_protocol to have been called
        if self._transport_tasks:
            if _debug:
                IPv6DatagramServer._debug(
                    "    - waiting for tasks: %r", self._transport_tasks
                )
            await asyncio.gather(*self._transport_tasks)
            self._transport_tasks = []

        # downstream packets can have a specific or local broadcast address
        use_multicast = isinstance(pdu.pduDestination, LocalBroadcast)
        if use_multicast:
            pdu_destination = self.broadcast_address
        elif isinstance(pdu.pduDestination, IPv6Address):
            pdu_destination = pdu.pduDestination.addrTuple
        else:
            raise ValueError(f"invalid destination: {pdu.pduDestination}")
        if _debug:
            IPv6DatagramServer._debug("    - pdu_destination: %r", pdu_destination)

        # wait for the local transport to be ready
        if not self._local_transport_ready.is_set():
            if _debug:
                IPv6DatagramServer._debug("    - waiting for local transport")
        await self._local_transport_ready.wait()

        # send it along; broadcast/multicast goes out the multicast socket so the
        # interface scope (and IPV6_MULTICAST_IF) keeps it on the local link
        try:
            if use_multicast and self.multicast_transport:
                self.multicast_transport.sendto(pdu.pduData, pdu_destination)
            else:
                assert self.transport
                self.transport.sendto(pdu.pduData, pdu_destination)
        except OSError as err:
            if _debug:
                IPv6DatagramServer._debug("    - sendto error: %r", err)
            if self.interface_name:
                asyncio.create_task(self._rebuild())


    async def confirmation(self, pdu: PDU) -> None:
        if _debug:
            IPv6DatagramServer._debug("confirmation %r", pdu)

        assert isinstance(pdu.pduSource, IPv6Address)
        if pdu.pduSource.addrTuple[:2] == self.local_address[:2]:
            if _debug:
                IPv6DatagramServer._debug("    - broadcast/reflected?")

        # up the stack it goes
        await self.response(pdu)

    def close(self) -> None:
        if _debug:
            IPv6DatagramServer._debug("close")

        # close the transports
        if self.transport:
            self.transport.close()
        if self.multicast_transport:
            self.multicast_transport.close()
