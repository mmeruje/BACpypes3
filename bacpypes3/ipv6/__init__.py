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

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if _debug:
            IPv6DatagramProtocol._debug("connection_lost %r", exc)


@bacpypes_debugging
class IPv6DatagramServer(Server[PDU]):
    _debug: Callable[..., None]
    _exception: Callable[..., None]
    _transport_tasks: List[Any]
    _local_transport_ready: asyncio.Event

    interface_index: int
    local_address: Tuple[str, int, int, int]
    broadcast_address: Tuple[str, int, int, int]
    transport: Optional[asyncio.DatagramTransport]
    protocol: Optional[IPv6DatagramProtocol]
    multicast_transport: Optional[asyncio.DatagramTransport]
    multicast_protocol: Optional[IPv6DatagramProtocol]

    def __init__(
        self,
        address: IPv6Address,
        multicast_groups: Optional[List[str]] = None,
    ) -> None:
        if _debug:
            IPv6DatagramServer._debug("__init__ %r %r", address, multicast_groups)

        # grab the loop to create tasks and endpoints
        loop: asyncio.events.AbstractEventLoop = asyncio.get_running_loop()

        # save the local address to check for reflections
        self.local_address = address.addrTuple
        if _debug:
            IPv6DatagramServer._debug("    - local_address: %r", self.local_address)

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
        if self.interface_index:
            local_socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self.interface_index
            )

        # bind to the specific address to force the source address
        local_socket.bind(self.local_address)

        # easy call to create a local endpoint
        local_endpoint_task = loop.create_task(
            self.retrying_create_datagram_endpoint(loop, local_socket)
        )
        if _debug:
            IPv6DatagramServer._debug(
                "    - local_endpoint_task: %r", local_endpoint_task
            )
        local_endpoint_task.add_done_callback(
            functools.partial(self.set_local_transport_protocol, address)
        )

        # keep a list of things that need to complete before sending stuff
        self._transport_tasks = [local_endpoint_task]
        self._local_transport_ready = asyncio.Event()

        # join the IANA assigned link-local multicast group
        if multicast_groups is None:
            multicast_groups = ["ff02::bac0"]

        # the first one is the broadcast address
        self.broadcast_address = cast(
            IPv6Address,
            IPv6Address(
                multicast_groups[0],
                port=self.local_address[1],
                interface=self.interface_index,
            ),
        ).addrTuple

        # if we are bound to the wildcard address, we can join the groups on the same socket
        if self.local_address[0] in ("::", "0:0:0:0:0:0:0:0"):
            for group in multicast_groups:
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
            multicast_socket = socket.socket(
                family=socket.AF_INET6, type=socket.SOCK_DGRAM
            )
            if _debug:
                IPv6DatagramServer._debug("    - multicast_socket: %r", multicast_socket)

            # make socket ipv6 only, leaving port free for ipv4 applications
            multicast_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            # allow multiple applications to use the same port
            multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            # join the groups
            for group in multicast_groups:
                if _debug:
                    IPv6DatagramServer._debug("    - join group: %r", group)
                multicast_socket.setsockopt(
                    socket.IPPROTO_IPV6,
                    socket.IPV6_JOIN_GROUP,
                    struct.pack(
                        "16sI",
                        socket.inet_pton(socket.AF_INET6, group),
                        self.interface_index,
                    ),
                )

            # disable multicast loopback
            multicast_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

            # bind to the wildcard address to receive multicast
            multicast_socket.bind(("", self.local_address[1], 0, self.interface_index))

            # create the multicast endpoint
            multicast_endpoint_task = loop.create_task(
                self.retrying_create_datagram_endpoint(loop, multicast_socket)
            )
            if _debug:
                IPv6DatagramServer._debug(
                    "    - multicast_endpoint_task: %r", multicast_endpoint_task
                )
            multicast_endpoint_task.add_done_callback(
                functools.partial(self.set_multicast_transport_protocol, address)
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

    def set_local_transport_protocol(self, address: IPv6Address, task: asyncio.Task) -> None:
        if _debug:
            IPv6DatagramServer._debug(
                "set_local_transport_protocol %r, %r", address, task
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

    def set_multicast_transport_protocol(self, address: IPv6Address, task: asyncio.Task) -> None:
        if _debug:
            IPv6DatagramServer._debug(
                "set_multicast_transport_protocol %r, %r", address, task
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
        if isinstance(pdu.pduDestination, LocalBroadcast):
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

        # send it along
        assert self.transport
        self.transport.sendto(pdu.pduData, pdu_destination)


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
